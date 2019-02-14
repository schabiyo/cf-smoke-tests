package services

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/cloudfoundry-incubator/cf-test-helpers/workflowhelpers"
	"github.com/schabiyo/cf-smoke-tests/smoke"
)

func TestSmokeTests(t *testing.T) {
	RegisterFailHandler(Fail)

	testConfig := smoke.GetConfig()
	testSetup := workflowhelpers.NewSmokeTestSuiteSetup(testConfig)

	SynchronizedBeforeSuite(func() []byte {
		testSetup.Setup()
		return nil
	}, func(data []byte) {})

	SynchronizedAfterSuite(func() {
	}, func() {
		testSetup.Teardown()
	})

	rs := []Reporter{}

	if testConfig.ArtifactsDirectory != "" {
		os.Setenv("CF_TRACE", traceLogFilePath(testConfig))
		rs = append(rs, reporters.NewJUnitReporter(jUnitReportFilePath(testConfig)))
	}

	if testConfig.Reporter == "TeamCity" {
		rs = append(rs, reporters.NewTeamCityReporter(GinkgoWriter))
	}

	RunSpecsWithDefaultAndCustomReporters(t, "CF-Services-Smoke-Tests", rs)
}

func traceLogFilePath(testConfig *smoke.Config) string {
	return filepath.Join(testConfig.ArtifactsDirectory, fmt.Sprintf("CF-TRACE-%s-%d.txt", testConfig.SuiteName, ginkgoNode()))
}

func jUnitReportFilePath(testConfig *smoke.Config) string {
	return filepath.Join(testConfig.ArtifactsDirectory, fmt.Sprintf("junit-%s-%d.xml", testConfig.SuiteName, ginkgoNode()))
}

func ginkgoNode() int {
	return ginkgoconfig.GinkgoConfig.ParallelNode
}
