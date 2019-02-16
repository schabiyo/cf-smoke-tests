package services

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfoundry-incubator/cf-test-helpers/cf"
	"github.com/cloudfoundry-incubator/cf-test-helpers/generator"
	"github.com/schabiyo/cf-smoke-tests/smoke"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("BackendServices:", func() {
	var testConfig = smoke.GetConfig()
	var appName string
	var ssoServiceName string
	var sccServiceName string
	var azureDBServiceName string
	var appURL string
	var expectedNullResponse string

	BeforeEach(func() {
		appName = testConfig.RuntimeApp
		sccServiceName = testConfig.SCCService
		azureDBServiceName = testConfig.AzureDBService
		if appName == "" {
			appName = generator.PrefixedRandomName("SMOKES", "APP")
		}
		appURL = "https://" + appName + "." + testConfig.AppsDomain

		if sccServiceName == "" {
			sccServiceName = generator.PrefixedRandomName("SMOKES-SCC", "SRC")
		}
		if azureDBServiceName == "" {
			azureDBServiceName = generator.PrefixedRandomName("SMOKES-AZUREDB", "SRC")
		}
		if ssoServiceName == "" {
			ssoServiceName = generator.PrefixedRandomName("SMOKES-SSO", "SRC")
		}
		Eventually(func() error {
			var err error
			expectedNullResponse, err = getBodySkipSSL(testConfig.SkipSSLValidation, appURL)
			return err
		}, testConfig.GetDefaultTimeout()).Should(BeNil())
	})

	AfterEach(func() {
		defer func() {
			if testConfig.Cleanup {
				Expect(cf.Cf("delete", appName, "-f", "-r").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
				//Delete the services
				if testConfig.GetEnableSCCTests() {
					Expect(cf.Cf("delete-service", sccServiceName, "-f").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
				}
				if testConfig.GetEnableAzureDBTests() {
					Expect(cf.Cf("delete-service", azureDBServiceName, "-f").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
				}
				if testConfig.GetEnableSSOAuthCodeTests() {
					Expect(cf.Cf("delete-service", ssoServiceName, "-f").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
				}
			}
		}()
		smoke.AppReport(appName, testConfig.GetDefaultTimeout())
	})
	Context("Spring Cloud Service Configs service", func() {
		It("can be created, used and deleted", func() {
			// Create the service
			Expect(cf.Cf("create-service", "p-config-server", "standard", sccServiceName, "-c", smoke.SCCJavaAppBitsPath+"/scc.json").Wait(testConfig.GetServiceCreateTimeout())).To(Exit(0))
			var state int
			//var result string
			for ok := true; ok; ok = (state != 1) {
				services := cf.Cf("service", sccServiceName).Wait(testConfig.GetPushTimeout())
				servicesOutput := string(services.Out.Contents())
				if strings.Contains(servicesOutput, "succeeded") {
					break
				}
				time.Sleep(10 * time.Second)
			}
			// Deploy the app
			Expect(cf.Cf("push", "-b", "java_buildpack_offline", appName, "-p", smoke.SCCJavaAppBitsPath+"/cook-0.0.1-SNAPSHOT.jar", "-d", testConfig.AppsDomain, "--no-start").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Set ENV Variable to disable Basic authentication since I'm usingh the cook app here
			Expect(cf.Cf("set-env", appName, "SPRING_PROFILES_ACTIVE", "development").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Bind to the service
			Expect(cf.Cf("bind-service", appName, sccServiceName, testConfig.AppsDomain).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Start the app
			Expect(cf.Cf("restart", appName).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			// Hit the restaurant endpoint
			runPushTests(appName, appURL+"/restaurant", sccServiceName, "Awesome!! Config successfully read from Git", expectedNullResponse, testConfig)
		})
	})

	Context("Azure SQL service", func() {
		BeforeEach(func() {
			if testConfig.GetEnableAzureDBTests() != true {
				Skip("Skipping because EnableAzureDBTests flag is set to false")
			}
		})
		It("can be created, used and deleted", func() {
			smoke.SkipIfNotWindows(testConfig)
			// Create the service
			Expect(cf.Cf("create-service", "azure-sqldb", "basic", azureDBServiceName, "-c", smoke.MssqlDotnetAppBitsPath+"/sqldb-config.json").Wait(testConfig.GetServiceCreateTimeout())).To(Exit(0))
			// Push the app
			//Expect(cf.Cf("push", appName, "-p", smoke.SimpleDotnetAppBitsPath, "-d", testConfig.AppsDomain, "-s", testConfig.GetWindowsStack(), "-b", "hwc_buildpack").Wait(testConfig.GetPushTimeout())).To(Exit(0))

			//runPushTests(appName, appURL, "Azure DB rocks!", expectedNullResponse, testConfig)
		})
	})
	Context("SSO service -- Authentication Code", func() {
		BeforeEach(func() {
			if testConfig.GetEnableSSOAuthCodeTests() != true {
				Skip("Skipping because EnableSSOTests flag is set to false")
			}
		})
		//Auth code and client credential will be tested
		It("is working as expected", func() {
			//smoke.SkipIfNotWindows(testConfig)
			// Create the UAA service
			Expect(cf.Cf("create-service", "p-identity", testConfig.GetSSOPlan(), ssoServiceName).Wait(testConfig.GetServiceCreateTimeout())).To(Exit(0))
			// Push the app
			//Expect(cf.Cf("push", appName, "-p", smoke.SimpleDotnetAppBitsPath, "-d", testConfig.AppsDomain, "-s", testConfig.GetWindowsStack(), "-b", "hwc_buildpack").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//runPushTests(appName, appURL, "auth_time", expectedNullResponse, testConfig)
		})
	})

	Context("SSO service -- Client Credential ", func() {
		BeforeEach(func() {
			if testConfig.GetEnableSSOClientCredTests() != true {
				Skip("Skipping because EnableSSOClientCredTests flag is set to false")
			}
		})
		//Auth code and client credential will be tested
		It("can be created, used and deleted", func() {
			//smoke.SkipIfNotWindows(testConfig)
			// Create the UAA service
			Expect(cf.Cf("create-service", "p-identity", testConfig.GetSSOPlan(), ssoServiceName).Wait(testConfig.GetServiceCreateTimeout())).To(Exit(0))
			// Push the app
			//Expect(cf.Cf("push", appName, "-p", smoke.SimpleDotnetAppBitsPath, "-d", testConfig.AppsDomain, "-s", testConfig.GetWindowsStack(), "-b", "hwc_buildpack").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//runPushTests(appName, appURL, "auth_time", expectedNullResponse, testConfig)
		})
	})
})

func runPushTests(appName, appURL, serviceName, expectedResponse, expectedNullResponse string, testConfig *smoke.Config) {
	Eventually(func() (string, error) {
		return getBodySkipSSL(testConfig.SkipSSLValidation, appURL)
	}, testConfig.GetDefaultTimeout()).Should(ContainSubstring(expectedResponse))

	if testConfig.Cleanup {
		Expect(cf.Cf("delete", appName, "-f", "-r").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))

		Eventually(func() (string, error) {
			return getBodySkipSSL(testConfig.SkipSSLValidation, appURL)
		}, testConfig.GetDefaultTimeout()).Should(ContainSubstring(string(expectedNullResponse)))
		//Delete the services as well
		if testConfig.GetEnableSCCTests() {
			Expect(cf.Cf("delete-service", serviceName, "-f").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
		}
	}
}

// Gets app status (up to maxAttempts) until all instances are up
func ExpectAllAppInstancesToStart(appName string, instances int, maxAttempts int, timeout time.Duration) {
	var found bool
	expectedOutput := regexp.MustCompile(fmt.Sprintf(`instances:\s+%d/%d`, instances, instances))

	outputMatchers := make([]*regexp.Regexp, instances)
	for i := 0; i < instances; i++ {
		outputMatchers[i] = regexp.MustCompile(fmt.Sprintf(`#%d\s+running`, i))
	}

	for i := 0; i < maxAttempts; i++ {
		session := cf.Cf("app", appName)
		Expect(session.Wait(timeout)).To(Exit(0))

		output := string(session.Out.Contents())
		found = expectedOutput.MatchString(output)

		if found {
			for _, matcher := range outputMatchers {
				matches := matcher.FindStringSubmatch(output)
				if matches == nil {
					found = false
					break
				}
			}
		}

		if found {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	Expect(found).To(BeTrue(), fmt.Sprintf("Wanted to see '%s' (all instances running) in %d attempts, but didn't", expectedOutput, maxAttempts))
}

func allTrue(bools []bool) bool {
	for _, curr := range bools {
		if !curr {
			return false
		}
	}
	return true
}

func getBodySkipSSL(skip bool, url string) (string, error) {
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skip},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
