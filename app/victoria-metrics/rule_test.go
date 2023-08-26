package main

// import (
// 	"bytes"
// 	"encoding/json"
// 	// "flag"
// 	"fmt"
// 	"net/http"
// 	"os"
// 	"path/filepath"
// 	"sort"
// 	"strings"
// 	"testing"
// 	"time"

// 	// "io"
// 	// "log"
// 	// "net"
// 	// "net/http"
// 	"gopkg.in/yaml.v2"

// 	// "reflect"

// 	testutil "github.com/VictoriaMetrics/VictoriaMetrics/app/victoria-metrics/test"
// 	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmstorage"
// 	// "github.com/VictoriaMetrics/VictoriaMetrics/lib/fs"
// 	// "github.com/VictoriaMetrics/VictoriaMetrics/lib/httpserver"
// 	vmalertconfig "github.com/VictoriaMetrics/VictoriaMetrics/app/vmalert/config"
// 	"github.com/VictoriaMetrics/VictoriaMetrics/app/vmalert/notifier"
// 	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"

// 	// "github.com/VictoriaMetrics/metricsql"

// 	prommodel "github.com/prometheus/common/model"
// 	promlabel "github.com/prometheus/prometheus/model/labels"
// 	promparser "github.com/prometheus/prometheus/promql/parser"
// )

// var testStartTime = time.Unix(0, 0).UTC()

// type ruleTest struct {
// 	Name             string     `json:"name"`
// 	Data             []NewInput `json:"data"`
// 	InsertQuery      string     `json:"insert_query"`
// 	Query            []string   `json:"query"`
// 	ResultMetrics    []Metric   `json:"result_metrics"`
// 	ResultSeries     Series     `json:"result_series"`
// 	ResultQuery      Query      `json:"result_query"`
// 	ResultQueryRange QueryRange `json:"result_query_range"`
// 	Issue            string     `json:"issue"`
// }

// type NewInput struct {
// 	Interval prommodel.Duration `json:"interval"`
// 	Series   string             `json:"series"`
// 	Values   string             `json:"values"`
// }

// func TestRuleWriteRead(t *testing.T) {
// 	RulesUnitTest([]string{"./testdata/ruletest/test.yaml"}...)
// 	testRuleWrite()
// 	vmstorage.Storage.DebugFlush()
// 	time.Sleep(1 * time.Second)
// 	// t.Run("read", testRuleExec)
// }

// func testRuleWrite() {
// 	tmp := readRuleIn("ruletest")
// 	for _, test2 := range tmp {
// 		r := testutil.WriteRequest{}
// 		for _, data := range test2.Data {
// 			result := fmt.Sprintf("%v %v\n", data.Series, data.Values)
// 			prommetric, promvals, err := promparser.ParseSeriesDesc(result)
// 			if err != nil {
// 			}
// 			// fmt.Println(prommetric, promvals)
// 			// expr, err := metricsql.Parse(data.Series)
// 			// fmt.Println(expr)
// 			// if err != nil {
// 			// }
// 			// exp := expr.(*metricsql.MetricExpr)
// 			samples := make([]testutil.Sample, 0, len(promvals))
// 			ts := testStartTime
// 			// ts := testStartTime.Add(-time.Duration(len(promvals)) * time.Duration(data.Interval))
// 			for _, v := range promvals {
// 				if !v.Omitted {
// 					samples = append(samples, testutil.Sample{
// 						Timestamp: ts.UnixNano() / int64(time.Millisecond/time.Nanosecond),
// 						Value:     v.Value,
// 					})
// 				}
// 				ts = ts.Add(time.Duration(data.Interval))
// 			}
// 			var ls []testutil.Label
// 			for _, filter := range prommetric {
// 				ls = append(ls, testutil.Label{Name: filter.Name, Value: filter.Value})
// 			}
// 			r.Timeseries = append(r.Timeseries, testutil.TimeSeries{Labels: ls, Samples: samples})
// 		}

// 		// todo 把规则 转换为AlertingRule/RecordingRule，然后调用他们的execRange得到新的timeseries写回去
// 		// 然后查就好啦，recording查名称，alert查ALERTS??

// 		// s.noError(json.Unmarshal([]byte(strings.Join(test.Data, "\n")), &r.Timeseries))
// 		data, err := testutil.Compress(r)
// 		if err != nil {
// 			logger.Panicf("error compressing %v %s", r, err)
// 		}
// 		resp, err := http.Post(testPromWriteHTTPPath+test2.InsertQuery, "", bytes.NewBuffer(data))
// 		defer resp.Body.Close()
// 		if err != nil {
// 			logger.Errorf("%v", err)
// 		}
// 	}
// }

// // func testRuleExec(t *testing.T) {
// // 	// t.Run(engine, func(t *testing.T) {
// // 	tmp := readRuleIn("ruletest")
// // 	for _, x := range tmp {
// // 		test := x
// // 		t.Run(test.Name, func(t *testing.T) {
// // 			for _, q := range test.Query {
// // 				q = testutil.PopulateTimeTplString(q, insertionTime)
// // 				if test.Issue != "" {
// // 					test.Issue = "\nRegression in " + test.Issue
// // 				}
// // 				switch true {
// // 				case strings.HasPrefix(q, "/api/v1/export"):
// // 					if err := checkMetricsResult(httpReadMetrics(t, testReadHTTPPath, q), test.ResultMetrics); err != nil {
// // 						t.Fatalf("Export. %s fails with error %s.%s", q, err, test.Issue)
// // 					}
// // 				case strings.HasPrefix(q, "/api/v1/series"):
// // 					s := Series{}
// // 					httpReadStruct(t, testReadHTTPPath, q, &s)
// // 					if err := checkSeriesResult(s, test.ResultSeries); err != nil {
// // 						t.Fatalf("Series. %s fails with error %s.%s", q, err, test.Issue)
// // 					}
// // 				case strings.HasPrefix(q, "/api/v1/query_range"):
// // 					queryResult := QueryRange{}
// // 					httpReadStruct(t, testReadHTTPPath, q, &queryResult)
// // 					if err := checkQueryRangeResult(queryResult, test.ResultQueryRange); err != nil {
// // 						t.Fatalf("Query Range. %s fails with error %s.%s", q, err, test.Issue)
// // 					}
// // 				case strings.HasPrefix(q, "/api/v1/query"):
// // 					queryResult := Query{}
// // 					time.Sleep(100 * time.Second)
// // 					httpReadStruct(t, testReadHTTPPath, q, &queryResult)
// // 					logger.Infof("%v\n", "wang")
// // 					logger.Infof("%v", queryResult.Data)
// // 					// httpReadStruct(t, testReadHTTPPath, q, &queryResult)
// // 					time.Sleep(200 * time.Second)

// // 					if err := checkQueryResult(queryResult, test.ResultQuery); err != nil {
// // 						t.Fatalf("Query. %s fails with error: %s.%s", q, err, test.Issue)
// // 					}
// // 				default:
// // 					t.Fatalf("unsupported read query %s", q)
// // 				}
// // 			}
// // 		})
// // 	}
// // }

// func readRuleIn(readFor string) []ruleTest {
// 	var tt []ruleTest
// 	filepath.Walk(filepath.Join(testFixturesDir, readFor), func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}
// 		if filepath.Ext(path) != ".json" {
// 			return nil
// 		}
// 		b, err := os.ReadFile(path)
// 		if err != nil {
// 			logger.Errorf("%v", err)
// 		}
// 		item := ruleTest{}
// 		err = json.Unmarshal(b, &item)
// 		if err != nil {
// 			logger.Errorf("%v", err)
// 		}
// 		tt = append(tt, item)
// 		return nil
// 	})
// 	if len(tt) == 0 {
// 		logger.Fatalf("no test found in %s", filepath.Join(testFixturesDir, readFor))
// 	}
// 	return tt
// }

// // RulesUnitTest does unit testing of rules based on the unit testing files provided.
// // More info about the file format can be found in the docs.
// func RulesUnitTest(files ...string) int {
// 	failed := false

// 	for _, f := range files {
// 		if errs := ruleUnitTest(f); errs != nil {
// 			fmt.Fprintln(os.Stderr, "  FAILED:")
// 			for _, e := range errs {
// 				fmt.Fprintln(os.Stderr, e.Error())
// 				fmt.Println()
// 			}
// 			failed = true
// 		} else {
// 			fmt.Println("  SUCCESS")
// 		}
// 		fmt.Println()
// 	}
// 	if failed {
// 		return 1
// 	}
// 	return 0
// }

// // resolveAndGlobFilepaths joins all relative paths in a configuration
// // with a given base directory and replaces all globs with matching files.
// func resolveAndGlobFilepaths(baseDir string, utf *unitTestFile) error {
// 	for i, rf := range utf.RuleFiles {
// 		if rf != "" && !filepath.IsAbs(rf) {
// 			utf.RuleFiles[i] = filepath.Join(baseDir, rf)
// 		}
// 	}

// 	var globbedFiles []string
// 	for _, rf := range utf.RuleFiles {
// 		m, err := filepath.Glob(rf)
// 		if err != nil {
// 			return err
// 		}
// 		if len(m) == 0 {
// 			fmt.Fprintln(os.Stderr, "  WARNING: no file match pattern", rf)
// 		}
// 		globbedFiles = append(globbedFiles, m...)
// 	}
// 	utf.RuleFiles = globbedFiles
// 	return nil
// }

// func ruleUnitTest(filename string) []error {
// 	fmt.Println("Unit Testing: ", filename)

// 	b, err := os.ReadFile(filename)
// 	if err != nil {
// 		return []error{err}
// 	}

// 	var unitTestInp unitTestFile
// 	if err := yaml.UnmarshalStrict(b, &unitTestInp); err != nil {
// 		return []error{err}
// 	}
// 	if err := resolveAndGlobFilepaths(filepath.Dir(filename), &unitTestInp); err != nil {
// 		return []error{err}
// 	}

// 	if unitTestInp.EvaluationInterval == 0 {
// 		unitTestInp.EvaluationInterval = prommodel.Duration(1 * time.Minute)
// 	}

// 	evalInterval := time.Duration(unitTestInp.EvaluationInterval)

// 	// Giving number for groups mentioned in the file for ordering.
// 	// Lower number group should be evaluated before higher number group.
// 	groupOrderMap := make(map[string]int)
// 	for i, gn := range unitTestInp.GroupEvalOrder {
// 		if _, ok := groupOrderMap[gn]; ok {
// 			return []error{fmt.Errorf("group name repeated in evaluation order: %s", gn)}
// 		}
// 		groupOrderMap[gn] = i
// 	}

// 	// Testing.
// 	var errs []error
// 	for _, t := range unitTestInp.Tests {
// 		fmt.Println(t, evalInterval)
// 		ers := t.test(evalInterval, groupOrderMap, queryOpts, unitTestInp.RuleFiles...)
// 		// if ers != nil {
// 		// 	errs = append(errs, ers...)
// 		// }
// 	}

// 	if len(errs) > 0 {
// 		return errs
// 	}
// 	return nil
// }

// // unitTestFile holds the contents of a single unit test file.
// type unitTestFile struct {
// 	RuleFiles          []string           `yaml:"rule_files"`
// 	EvaluationInterval prommodel.Duration `yaml:"evaluation_interval,omitempty"`
// 	GroupEvalOrder     []string           `yaml:"group_eval_order"`
// 	Tests              []testGroup        `yaml:"tests"`
// }

// // testGroup is a group of input series and tests associated with it.
// type testGroup struct {
// 	Interval        prommodel.Duration `yaml:"interval"`
// 	InputSeries     []series           `yaml:"input_series"`
// 	AlertRuleTests  []alertTestCase    `yaml:"alert_rule_test,omitempty"`
// 	PromqlExprTests []promqlTestCase   `yaml:"promql_expr_test,omitempty"`
// 	ExternalLabels  promlabel.Labels   `yaml:"external_labels,omitempty"`
// 	ExternalURL     string             `yaml:"external_url,omitempty"`
// 	TestGroupName   string             `yaml:"name,omitempty"`
// }

// // maxEvalTime returns the max eval time among all alert and promql unit tests.
// func (tg *testGroup) maxEvalTime() time.Duration {
// 	var maxd prommodel.Duration
// 	for _, alert := range tg.AlertRuleTests {
// 		if alert.EvalTime > maxd {
// 			maxd = alert.EvalTime
// 		}
// 	}
// 	for _, pet := range tg.PromqlExprTests {
// 		if pet.EvalTime > maxd {
// 			maxd = pet.EvalTime
// 		}
// 	}
// 	return time.Duration(maxd)
// }

// type series struct {
// 	Series string `yaml:"series"`
// 	Values string `yaml:"values"`
// }

// type alertTestCase struct {
// 	EvalTime  prommodel.Duration `yaml:"eval_time"`
// 	Alertname string             `yaml:"alertname"`
// 	ExpAlerts []alert            `yaml:"exp_alerts"`
// }

// type alert struct {
// 	ExpLabels      map[string]string `yaml:"exp_labels"`
// 	ExpAnnotations map[string]string `yaml:"exp_annotations"`
// }

// type promqlTestCase struct {
// 	Expr       string             `yaml:"expr"`
// 	EvalTime   prommodel.Duration `yaml:"eval_time"`
// 	ExpSamples []sample           `yaml:"exp_samples"`
// }

// type sample struct {
// 	Labels string  `yaml:"labels"`
// 	Value  float64 `yaml:"value"`
// }

// // ManagerOptions bundles options for the Manager.
// type ManagerOptions struct {
// 	// ExternalURL     *url.URL
// 	// QueryFunc       QueryFunc
// 	// NotifyFunc      NotifyFunc
// 	// Context         context.Context
// 	// Appendable      storage.Appendable
// 	// Queryable       storage.Queryable
// 	// Logger          log.Logger
// 	// Registerer      prometheus.Registerer
// 	OutageTolerance time.Duration
// 	ForGracePeriod  time.Duration
// 	ResendDelay     time.Duration
// 	// GroupLoader     GroupLoader

// 	// Metrics *Metrics
// }

// func (tg *testGroup) test(evalInterval time.Duration, groupOrderMap map[string]int, queryOpts promql.LazyLoaderOpts, ruleFiles ...string) error {
// 	// Setup testing suite.
// 	// suite, err := promql.NewLazyLoader(nil, tg.seriesLoadingString(), queryOpts)
// 	// if err != nil {
// 	// 	return []error{err}
// 	// }
// 	// defer suite.Close()
// 	// suite.SubqueryInterval = evalInterval

// 	// // Load the rule files.
// 	// opts := &rules.ManagerOptions{
// 	// 	QueryFunc:  rules.EngineQueryFunc(suite.QueryEngine(), suite.Storage()),
// 	// 	Appendable: suite.Storage(),
// 	// 	Context:    context.Background(),
// 	// 	NotifyFunc: func(ctx context.Context, expr string, alerts ...*rules.Alert) {},
// 	// 	Logger:     log.NewNopLogger(),
// 	// }
// 	groups, err := vmalertconfig.Parse(ruleFiles, notifier.ValidateTemplates, true)
// 	// m := rules.NewManager(opts)
// 	// groupsMap, ers := m.LoadGroups(time.Duration(tg.Interval), tg.ExternalLabels, tg.ExternalURL, nil, ruleFiles...)
// 	if err != nil {
// 		return err
// 	}
// 	// groups := orderedGroups(groupsMap, groupOrderMap)

// 	// Bounds for evaluating the rules.
// 	mint := time.Unix(0, 0).UTC()
// 	// 拿到规则中eval_time最大的值，比如10m
// 	maxt := mint.Add(tg.maxEvalTime())

// 	// Pre-processing some data for testing alerts.
// 	// All this preparation is so that we can test alerts as we evaluate the rules.
// 	// This avoids storing them in memory, as the number of evals might be high.

// 	// All the `eval_time` for which we have unit tests for alerts.
// 	alertEvalTimesMap := map[prommodel.Duration]struct{}{}
// 	// Map of all the eval_time+alertname combination present in the unit tests.
// 	alertsInTest := make(map[prommodel.Duration]map[string]struct{})
// 	// Map of all the unit tests for given eval_time.
// 	alertTests := make(map[prommodel.Duration][]alertTestCase)
// 	for _, alert := range tg.AlertRuleTests {
// 		if alert.Alertname == "" {
// 			var testGroupLog string
// 			if tg.TestGroupName != "" {
// 				testGroupLog = fmt.Sprintf(" (in TestGroup %s)", tg.TestGroupName)
// 			}
// 			return fmt.Errorf("an item under alert_rule_test misses required attribute alertname at eval_time %v%s", alert.EvalTime, testGroupLog)
// 		}
// 		alertEvalTimesMap[alert.EvalTime] = struct{}{}

// 		if _, ok := alertsInTest[alert.EvalTime]; !ok {
// 			alertsInTest[alert.EvalTime] = make(map[string]struct{})
// 		}
// 		alertsInTest[alert.EvalTime][alert.Alertname] = struct{}{}

// 		alertTests[alert.EvalTime] = append(alertTests[alert.EvalTime], alert)
// 	}
// 	alertEvalTimes := make([]prommodel.Duration, 0, len(alertEvalTimesMap))
// 	for k := range alertEvalTimesMap {
// 		alertEvalTimes = append(alertEvalTimes, k)
// 	}
// 	sort.Slice(alertEvalTimes, func(i, j int) bool {
// 		return alertEvalTimes[i] < alertEvalTimes[j]
// 	})

// 	// Current index in alertEvalTimes what we are looking at.
// 	curr := 0

// 	for _, g := range groups {
// 		for _, r := range g.Rules {
// 			if r.Alert != "" {
// 				// Mark alerting rules as restored, to ensure the ALERTS timeseries is
// 				// created when they run.
// 				// 没看懂，干啥的

// 				// r.SetRestored(true)
// 			}
// 		}
// 	}

// 	var errs []error
// 	for ts := mint; ts.Before(maxt) || ts.Equal(maxt); ts = ts.Add(evalInterval) {
// 		// Collects the alerts asked for unit testing.
// 		var evalErrs []error
// 		// suite.WithSamplesTill(ts, func(err error) {
// 		// if err != nil {
// 		// 	errs = append(errs, err)
// 		// 	return
// 		// }
// 		for _, g := range groups {
// 			// todo 把规则 转换为AlertingRule/RecordingRule，然后调用他们的execRange得到新的timeseries写回去[类似于replay]
// 			// 然后查就好啦，recording查名称，alert查ALERTS??
// 			// 去算rules.yml里面定义的recording/alerting rule, evalInterval定义在unittest.yml的evaluation_interval里
// 			g.Eval(suite.Context(), ts)
// 			for _, r := range g.Rules() {
// 				if r.LastError() != nil {
// 					evalErrs = append(evalErrs, fmt.Errorf("    rule: %s, time: %s, err: %v",
// 						r.Name(), ts.Sub(time.Unix(0, 0).UTC()), r.LastError()))
// 				}
// 			}
// 		}
// 		// })
// 		errs = append(errs, evalErrs...)
// 		// Only end testing at this point if errors occurred evaluating above,
// 		// rather than any test failures already collected in errs.
// 		if len(evalErrs) > 0 {
// 			return errs
// 		}

// 		for {
// 			if !(curr < len(alertEvalTimes) && ts.Sub(mint) <= time.Duration(alertEvalTimes[curr]) &&
// 				time.Duration(alertEvalTimes[curr]) < ts.Add(evalInterval).Sub(mint)) {
// 				break
// 			}

// 			// We need to check alerts for this time.
// 			// If 'ts <= `eval_time=alertEvalTimes[curr]` < ts+evalInterval'
// 			// then we compare alerts with the Eval at `ts`.
// 			t := alertEvalTimes[curr]

// 			presentAlerts := alertsInTest[t]
// 			got := make(map[string]labelsAndAnnotations)

// 			// Same Alert name can be present in multiple groups.
// 			// Hence we collect them all to check against expected alerts.
// 			for _, g := range groups {
// 				grules := g.Rules()
// 				for _, r := range grules {
// 					ar, ok := r.(*rules.AlertingRule)
// 					if !ok {
// 						continue
// 					}
// 					if _, ok := presentAlerts[ar.Name()]; !ok {
// 						continue
// 					}

// 					var alerts labelsAndAnnotations
// 					for _, a := range ar.ActiveAlerts() {
// 						if a.State == rules.StateFiring {
// 							alerts = append(alerts, labelAndAnnotation{
// 								Labels:      a.Labels.Copy(),
// 								Annotations: a.Annotations.Copy(),
// 							})
// 						}
// 					}

// 					got[ar.Name()] = append(got[ar.Name()], alerts...)
// 				}
// 			}

// 			for _, testcase := range alertTests[t] {
// 				// Checking alerts.
// 				gotAlerts := got[testcase.Alertname]

// 				var expAlerts labelsAndAnnotations
// 				for _, a := range testcase.ExpAlerts {
// 					// User gives only the labels from alerting rule, which doesn't
// 					// include this label (added by Prometheus during Eval).
// 					if a.ExpLabels == nil {
// 						a.ExpLabels = make(map[string]string)
// 					}
// 					a.ExpLabels[labels.AlertName] = testcase.Alertname

// 					expAlerts = append(expAlerts, labelAndAnnotation{
// 						Labels:      labels.FromMap(a.ExpLabels),
// 						Annotations: labels.FromMap(a.ExpAnnotations),
// 					})
// 				}

// 				sort.Sort(gotAlerts)
// 				sort.Sort(expAlerts)

// 				if !reflect.DeepEqual(expAlerts, gotAlerts) {
// 					var testName string
// 					if tg.TestGroupName != "" {
// 						testName = fmt.Sprintf("    name: %s,\n", tg.TestGroupName)
// 					}
// 					expString := indentLines(expAlerts.String(), "            ")
// 					gotString := indentLines(gotAlerts.String(), "            ")
// 					errs = append(errs, fmt.Errorf("%s    alertname: %s, time: %s, \n        exp:%v, \n        got:%v",
// 						testName, testcase.Alertname, testcase.EvalTime.String(), expString, gotString))
// 				}
// 			}

// 			curr++
// 		}
// 	}

// 	// Checking promql expressions.
// Outer:
// 	for _, testCase := range tg.PromqlExprTests {
// 		got, err := query(suite.Context(), testCase.Expr, mint.Add(time.Duration(testCase.EvalTime)),
// 			suite.QueryEngine(), suite.Queryable())
// 		if err != nil {
// 			errs = append(errs, fmt.Errorf("    expr: %q, time: %s, err: %s", testCase.Expr,
// 				testCase.EvalTime.String(), err.Error()))
// 			continue
// 		}

// 		var gotSamples []parsedSample
// 		for _, s := range got {
// 			gotSamples = append(gotSamples, parsedSample{
// 				Labels: s.Metric.Copy(),
// 				Value:  s.F,
// 			})
// 		}

// 		var expSamples []parsedSample
// 		for _, s := range testCase.ExpSamples {
// 			lb, err := parser.ParseMetric(s.Labels)
// 			if err != nil {
// 				err = fmt.Errorf("labels %q: %w", s.Labels, err)
// 				errs = append(errs, fmt.Errorf("    expr: %q, time: %s, err: %w", testCase.Expr,
// 					testCase.EvalTime.String(), err))
// 				continue Outer
// 			}
// 			expSamples = append(expSamples, parsedSample{
// 				Labels: lb,
// 				Value:  s.Value,
// 			})
// 		}

// 		sort.Slice(expSamples, func(i, j int) bool {
// 			return labels.Compare(expSamples[i].Labels, expSamples[j].Labels) <= 0
// 		})
// 		sort.Slice(gotSamples, func(i, j int) bool {
// 			return labels.Compare(gotSamples[i].Labels, gotSamples[j].Labels) <= 0
// 		})
// 		if !reflect.DeepEqual(expSamples, gotSamples) {
// 			errs = append(errs, fmt.Errorf("    expr: %q, time: %s,\n        exp: %v\n        got: %v", testCase.Expr,
// 				testCase.EvalTime.String(), parsedSamplesString(expSamples), parsedSamplesString(gotSamples)))
// 		}
// 	}

// 	if len(errs) > 0 {
// 		return errs
// 	}
// 	return nil
// }
