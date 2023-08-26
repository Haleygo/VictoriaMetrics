package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/fs"
	// "github.com/VictoriaMetrics/metricsql"

	// "io"
	// "log"
	// "net"
	// "net/http"
	"gopkg.in/yaml.v2"

	// "reflect"

	testutil "github.com/VictoriaMetrics/VictoriaMetrics/app/victoria-metrics/test"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmalert/datasource"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmalert/remotewrite"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vminsert"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmselect"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmselect/promql"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmstorage"

	// "github.com/VictoriaMetrics/VictoriaMetrics/lib/fs"
	// "github.com/VictoriaMetrics/VictoriaMetrics/lib/httpserver"
	vmalertconfig "github.com/VictoriaMetrics/VictoriaMetrics/app/vmalert/config"
	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmalert/notifier"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/httpserver"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"

	// "github.com/VictoriaMetrics/metricsql"

	prommodel "github.com/prometheus/common/model"
	promlabel "github.com/prometheus/prometheus/model/labels"
	promparser "github.com/prometheus/prometheus/promql/parser"
)

func TestRuleWriteRead(t *testing.T) {
	setUp()
	RulesUnitTest([]string{"./ruletest/test.yaml"}...)
	tearDown()
}

var testStartTime = time.Unix(0, 0).UTC()

var (
	storagePath   string
	insertionTime = time.Now().UTC()
)

const (
	testFixturesDir            = "ruletest"
	testStorageSuffix          = "vm-test-storage"
	testHTTPListenAddr         = ":7655"
	testStatsDListenAddr       = ":2004"
	testOpenTSDBListenAddr     = ":4244"
	testOpenTSDBHTTPListenAddr = ":4245"
	testLogLevel               = "INFO"
)

const (
	testReadHTTPPath          = "http://127.0.0.1" + testHTTPListenAddr
	testWriteHTTPPath         = "http://127.0.0.1" + testHTTPListenAddr + "/write"
	testOpenTSDBWriteHTTPPath = "http://127.0.0.1" + testOpenTSDBHTTPListenAddr + "/api/put"
	testPromWriteHTTPPath     = "http://127.0.0.1" + testHTTPListenAddr + "/api/v1/write"
	testHealthHTTPPath        = "http://127.0.0.1" + testHTTPListenAddr + "/health"
)

func processFlags() {
	flag.Parse()
	for _, fv := range []struct {
		flag  string
		value string
	}{
		{flag: "storageDataPath", value: storagePath},
		{flag: "httpListenAddr", value: testHTTPListenAddr},
		{flag: "graphiteListenAddr", value: testStatsDListenAddr},
		{flag: "opentsdbListenAddr", value: testOpenTSDBListenAddr},
		{flag: "loggerLevel", value: testLogLevel},
		{flag: "opentsdbHTTPListenAddr", value: testOpenTSDBHTTPListenAddr},
		{flag: "storageDataPath", value: storagePath},
		// set storage retention time to 100 years
		{flag: "retentionPeriod", value: "1200"},
		{flag: "datasource.url", value: "http://127.0.0.1:7655/prometheus"},
		{flag: "remoteWrite.url", value: "http://127.0.0.1:7655"},
	} {
		// panics if flag doesn't exist
		if err := flag.Lookup(fv.flag).Value.Set(fv.value); err != nil {
			log.Fatalf("unable to set %q with value %q, err: %v", fv.flag, fv.value, err)
		}
	}
}

func testrequestHandler(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/" {
		if r.Method != http.MethodGet {
			return false
		}
		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h2>Single-node VictoriaMetrics</h2></br>")
		fmt.Fprintf(w, "See docs at <a href='https://docs.victoriametrics.com/'>https://docs.victoriametrics.com/</a></br>")
		fmt.Fprintf(w, "Useful endpoints:</br>")
		httpserver.WriteAPIHelp(w, [][2]string{
			{"vmui", "Web UI"},
			{"targets", "status for discovered active targets"},
			{"service-discovery", "labels before and after relabeling for discovered targets"},
			{"metric-relabel-debug", "debug metric relabeling"},
			{"expand-with-exprs", "WITH expressions' tutorial"},
			{"api/v1/targets", "advanced information about discovered targets in JSON format"},
			{"config", "-promscrape.config contents"},
			{"metrics", "available service metrics"},
			{"flags", "command-line flags"},
			{"api/v1/status/tsdb", "tsdb status page"},
			{"api/v1/status/top_queries", "top queries"},
			{"api/v1/status/active_queries", "active queries"},
		})
		return true
	}
	if vminsert.RequestHandler(w, r) {
		return true
	}
	if vmselect.RequestHandler(w, r) {
		return true
	}
	if vmstorage.RequestHandler(w, r) {
		logger.Infof("wang %s", "test")
		return true
	}
	return false
}

func waitFor(timeout time.Duration, f func() bool) error {
	fraction := timeout / 10
	for i := fraction; i < timeout; i += fraction {
		if f() {
			return nil
		}
		time.Sleep(fraction)
	}
	return fmt.Errorf("timeout")
}

const (
	testStorageInitTimeout = 10 * time.Second
)

func setUp() {
	storagePath = filepath.Join(os.TempDir(), testStorageSuffix)
	processFlags()
	logger.Init()
	vmstorage.Init(promql.ResetRollupResultCacheIfNeeded)
	vmselect.Init()
	vminsert.Init()
	go httpserver.Serve(*httpListenAddr, false, testrequestHandler)
	readyStorageCheckFunc := func() bool {
		resp, err := http.Get(testHealthHTTPPath)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == 200
	}
	if err := waitFor(testStorageInitTimeout, readyStorageCheckFunc); err != nil {
		log.Fatalf("http server can't start for %s seconds, err %s", testStorageInitTimeout, err)
	}
}

func tearDown() {
	if err := httpserver.Stop(*httpListenAddr); err != nil {
		log.Printf("cannot stop the webservice: %s", err)
	}
	vminsert.Stop()
	vmstorage.Stop()
	vmselect.Stop()
	fs.MustRemoveAll(storagePath)
}

// RulesUnitTest does unit testing of rules based on the unit testing files provided.
// More info about the file format can be found in the docs.
func RulesUnitTest(files ...string) int {
	failed := false

	for _, f := range files {
		if errs := ruleUnitTest(f); errs != nil {
			fmt.Fprintln(os.Stderr, "  FAILED:")
			for _, e := range errs {
				fmt.Fprintln(os.Stderr, e.Error())
				fmt.Println()
			}
			failed = true
		} else {
			fmt.Println("  SUCCESS")
		}
		fmt.Println()
	}
	if failed {
		return 1
	}
	return 0
}

// resolveAndGlobFilepaths joins all relative paths in a configuration
// with a given base directory and replaces all globs with matching files.
func resolveAndGlobFilepaths(baseDir string, utf *unitTestFile) error {
	for i, rf := range utf.RuleFiles {
		if rf != "" && !filepath.IsAbs(rf) {
			utf.RuleFiles[i] = filepath.Join(baseDir, rf)
		}
	}

	var globbedFiles []string
	for _, rf := range utf.RuleFiles {
		m, err := filepath.Glob(rf)
		if err != nil {
			return err
		}
		if len(m) == 0 {
			fmt.Fprintln(os.Stderr, "  WARNING: no file match pattern", rf)
		}
		globbedFiles = append(globbedFiles, m...)
	}
	utf.RuleFiles = globbedFiles
	return nil
}

func ruleUnitTest(filename string) []error {
	fmt.Println("Unit Testing: ", filename)

	b, err := os.ReadFile(filename)
	if err != nil {
		return []error{err}
	}

	var unitTestInp unitTestFile
	if err := yaml.UnmarshalStrict(b, &unitTestInp); err != nil {
		return []error{err}
	}
	if err := resolveAndGlobFilepaths(filepath.Dir(filename), &unitTestInp); err != nil {
		return []error{err}
	}

	if unitTestInp.EvaluationInterval == 0 {
		unitTestInp.EvaluationInterval = prommodel.Duration(1 * time.Minute)
	}

	evalInterval := time.Duration(unitTestInp.EvaluationInterval)

	// Giving number for groups mentioned in the file for ordering.
	// Lower number group should be evaluated before higher number group.
	groupOrderMap := make(map[string]int)
	for i, gn := range unitTestInp.GroupEvalOrder {
		if _, ok := groupOrderMap[gn]; ok {
			return []error{fmt.Errorf("group name repeated in evaluation order: %s", gn)}
		}
		groupOrderMap[gn] = i
	}

	// Testing.
	var errs []error
	for _, t := range unitTestInp.Tests {
		fmt.Println(t, evalInterval)
		ers := t.test(evalInterval, groupOrderMap, unitTestInp.RuleFiles...)
		if ers != nil {
			errs = append(errs, []error{ers}...)
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// unitTestFile holds the contents of a single unit test file.
type unitTestFile struct {
	RuleFiles          []string           `yaml:"rule_files"`
	EvaluationInterval prommodel.Duration `yaml:"evaluation_interval,omitempty"`
	GroupEvalOrder     []string           `yaml:"group_eval_order"`
	Tests              []testGroup        `yaml:"tests"`
}

// testGroup is a group of input series and tests associated with it.
type testGroup struct {
	Interval        prommodel.Duration `yaml:"interval"`
	InputSeries     []series           `yaml:"input_series"`
	AlertRuleTests  []alertTestCase    `yaml:"alert_rule_test,omitempty"`
	PromqlExprTests []promqlTestCase   `yaml:"promql_expr_test,omitempty"`
	ExternalLabels  promlabel.Labels   `yaml:"external_labels,omitempty"`
	ExternalURL     string             `yaml:"external_url,omitempty"`
	TestGroupName   string             `yaml:"name,omitempty"`
}

// maxEvalTime returns the max eval time among all alert and promql unit tests.
func (tg *testGroup) maxEvalTime() time.Duration {
	var maxd prommodel.Duration
	for _, alert := range tg.AlertRuleTests {
		if alert.EvalTime > maxd {
			maxd = alert.EvalTime
		}
	}
	for _, pet := range tg.PromqlExprTests {
		if pet.EvalTime > maxd {
			maxd = pet.EvalTime
		}
	}
	return time.Duration(maxd)
}

type series struct {
	Series string `yaml:"series"`
	Values string `yaml:"values"`
}

type alertTestCase struct {
	EvalTime  prommodel.Duration `yaml:"eval_time"`
	Alertname string             `yaml:"alertname"`
	ExpAlerts []alert            `yaml:"exp_alerts"`
}

type alert struct {
	ExpLabels      map[string]string `yaml:"exp_labels"`
	ExpAnnotations map[string]string `yaml:"exp_annotations"`
}

type promqlTestCase struct {
	Expr       string             `yaml:"expr"`
	EvalTime   prommodel.Duration `yaml:"eval_time"`
	ExpSamples []sample           `yaml:"exp_samples"`
}

type sample struct {
	Labels string  `yaml:"labels"`
	Value  float64 `yaml:"value"`
}

func httpWrite(address string, r io.Reader) {
	resp, err := http.Post(address, "", r)
	if err != nil || resp.StatusCode != 204 {
		logger.Errorf("failed to send to storage: %v", err)
	}
	resp.Body.Close()
}

func (tg *testGroup) test(evalInterval time.Duration, groupOrderMap map[string]int, ruleFiles ...string) error {
	// todo defer cleanup data
	r := testutil.WriteRequest{}
	for _, data := range tg.InputSeries {
		result := fmt.Sprintf("%v %v\n", data.Series, data.Values)
		prommetric, promvals, err := promparser.ParseSeriesDesc(result)
		if err != nil {
			logger.Errorf("failed to parse series %v", err)
		}
		// fmt.Println(prommetric, promvals)
		// expr, err := metricsql.Parse(data.Series)
		// fmt.Println(expr)
		// if err != nil {
		// }
		// exp := expr.(*metricsql.MetricExpr)
		samples := make([]testutil.Sample, 0, len(promvals))
		ts := testStartTime
		for _, v := range promvals {
			if !v.Omitted {
				samples = append(samples, testutil.Sample{
					Timestamp: ts.UnixNano() / int64(time.Millisecond/time.Nanosecond),
					Value:     v.Value,
				})
			}
			ts = ts.Add(time.Duration(tg.Interval))
		}
		var ls []testutil.Label
		for _, filter := range prommetric {
			ls = append(ls, testutil.Label{Name: filter.Name, Value: filter.Value})
		}
		r.Timeseries = append(r.Timeseries, testutil.TimeSeries{Labels: ls, Samples: samples})
	}
	data, err := testutil.Compress(r)
	if err != nil {
		logger.Errorf("error compressing %v %s", r, err)
	}
	httpWrite(testPromWriteHTTPPath, bytes.NewBuffer(data))
	// flush replay result
	vmstorage.Storage.DebugFlush()

	groups, err := vmalertconfig.Parse(ruleFiles, notifier.ValidateTemplates, true)
	if err != nil {
		return err
	}

	time.Sleep(300 * time.Second)

	mint := time.Unix(0, 0).UTC()
	maxt := mint.Add(tg.maxEvalTime())

	q, err := datasource.Init(url.Values{"nocache": {"1"}})
	if err != nil {
		return err
	}
	rw, err := remotewrite.Init(context.Background())
	if err != nil {
		logger.Fatalf("failed to init remoteWrite: %s", err)
	}

	for _, g := range groups {
		ng := newGroup(g, q, *evaluationInterval, nil)
		// should got alert for rule InstanceUp/InstanceLongUp
		num := ng.replay(mint, maxt, rw)
		logger.Infof("replay got %d results", num)
	}
	vmstorage.Storage.DebugFlush()
	time.Sleep(100 * time.Second)

	queries := q.BuildWithParams(datasource.QuerierParams{DataSourceType: "prometheus", Debug: true})
	for _, ar := range tg.AlertRuleTests {
		expr := "ALERTS"
		expr = fmt.Sprintf("%s{alertname=\"%s\"}", expr, ar.Alertname)
		result, _, err := queries.Query(context.TODO(), expr, time.Unix(int64(time.Duration(ar.EvalTime).Seconds()), 0))
		if *result.SeriesFetched != 0 {
			logger.Infof("we got result for alert %s", ar.Alertname)
		}
		if err != nil {
			logger.Errorf("failed to query: %v", err)
		}
	}

	time.Sleep(300 * time.Second)

	// todo check result
	// todo check promql_expr
	return nil
}
