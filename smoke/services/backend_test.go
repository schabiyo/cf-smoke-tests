package services

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	//. "github.com/cloudfoundry-community/go-cfenv"
	"github.com/cloudfoundry-incubator/cf-test-helpers/cf"
	"github.com/cloudfoundry-incubator/cf-test-helpers/generator"
	"github.com/schabiyo/cf-smoke-tests/smoke"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var re = regexp.MustCompile("[-.+~`!@#$%^&*(){}\\[\\]:;\"',?<>/]")

type envvar struct {
	Key   string
	Value string
}

// Service is a VCAP_SERVICE instance
type Service struct {
	Name        string                 `json:"name"`
	Credentials map[string]interface{} `json:"credentials"`
}

type OauthCredential struct {
	AuthDomain   string `json:"auth_domain"`
	ClientSecret string `json:"client_secret"`
	ClientID     string `json:"client_id"`
}

var _ = Describe("BackendServices:", func() {
	var testConfig = smoke.GetConfig()
	var appName string
	var SSORessourceAppName string
	var SSOClientAppName string
	var ssoServiceName string
	var sccServiceName string
	var azureDBServiceName string
	var appURL string
	var expectedNullResponse string

	//var ssoCredentials Service

	BeforeEach(func() {
		appName = testConfig.RuntimeApp
		sccServiceName = testConfig.SCCService
		azureDBServiceName = testConfig.AzureDBService
		if appName == "" {
			appName = generator.PrefixedRandomName("SMOKES", "APP")
		}
		appURL = "https://" + appName + "." + testConfig.AppsDomain

		if SSOClientAppName == "" {
			SSOClientAppName = generator.PrefixedRandomName("SMOKES-CLIENT", "APP")
		}
		if SSORessourceAppName == "" {
			SSORessourceAppName = generator.PrefixedRandomName("SMOKES-RESSOURCE", "APP")
		}
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
				if testConfig.GetEnableSSOClientCredTests() {
					Expect(cf.Cf("delete", SSOClientAppName, "-f", "-r").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
					Expect(cf.Cf("delete", SSORessourceAppName, "-f", "-r").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
					Expect(cf.Cf("delete-service", ssoServiceName, "-f").Wait(testConfig.GetDefaultTimeout())).To(Exit(0))
				}
			}
		}()
		smoke.AppReport(appName, testConfig.GetDefaultTimeout())
	})
	Context("Spring Cloud Service Configs service", func() {
		BeforeEach(func() {
			if testConfig.GetEnableSCCTests() != true {
				Skip("Skipping because EnableSCCTests flag is set to false")
			}
		})
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
			Expect(cf.Cf("create-service", "azure-sqldb", "basic", azureDBServiceName, "-c", smoke.AzureDBlDotnetAppBitsPath+testConfig.GetAzureDBConfigFilename()).Wait(testConfig.GetServiceCreateTimeout())).To(Exit(0))
			var state int
			//var result string
			for ok := true; ok; ok = (state != 1) {
				services := cf.Cf("service", azureDBServiceName).Wait(testConfig.GetPushTimeout())
				servicesOutput := string(services.Out.Contents())
				if strings.Contains(servicesOutput, "succeeded") {
					break
				}
				time.Sleep(10 * time.Second)
			}
			// Push the app
			Expect(cf.Cf("push", appName, "-p", smoke.AzureDBlDotnetAppBitsPath+"ViewEnvironment", "-d", testConfig.AppsDomain, "-s", testConfig.GetWindowsStack(), "-b", "hwc_buildpack").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Bind to the service
			Expect(cf.Cf("bind-service", appName, azureDBServiceName, testConfig.AppsDomain).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Start the app
			Expect(cf.Cf("restart", appName).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			// Hit the restaurant endpoint
			runPushTests(appName, appURL, azureDBServiceName, "<span id=\"lblDbEngine\">SqlServer</span>", expectedNullResponse, testConfig)
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
			var appGUID, token string
			var creds OauthCredential
			// Create the UAA service
			Expect(cf.Cf("create-service", "p-identity", testConfig.GetSSOPlan(), ssoServiceName).Wait(testConfig.GetServiceCreateTimeout())).To(Exit(0))
			//Push the resource server
			Expect(cf.Cf("push", "-b", "java_buildpack_offline", SSORessourceAppName, "-p", smoke.SSOJavaAppBitsPath+"/resource-server.jar", "-f", smoke.SSOJavaAppBitsPath+"/resource-server.yml", "-d", testConfig.AppsDomain, "--no-start").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			// Push the credential app
			Expect(cf.Cf("push", "-b", "java_buildpack_offline", SSOClientAppName, "-p", smoke.SSOJavaAppBitsPath+"/client_credentials.jar", "-f", smoke.SSOJavaAppBitsPath+"/client_credentials.yml", "-d", testConfig.AppsDomain, "--no-start").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//SET the ENV fro the Client App
			Expect(cf.Cf("set-env", SSOClientAppName, "AUTH_SERVER", "https://manulife-dev.login.sys.cac.preview.pcf.manulife.com").Wait(testConfig.GetPushTimeout())).To(Exit(0))
			Expect(cf.Cf("set-env", SSOClientAppName, "SSO_IDENTITY_PROVIDERS", testConfig.GetSSOIdentityProvider()).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			Expect(cf.Cf("set-env", SSOClientAppName, "RESOURCE_URL", SSORessourceAppName+"."+testConfig.AppsDomain).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Bind to the service
			Expect(cf.Cf("bind-service", SSOClientAppName, ssoServiceName, testConfig.AppsDomain).Wait(testConfig.GetPushTimeout())).To(Exit(0))
			//Start the app
			Expect(cf.Cf("restart", SSOClientAppName).Wait(testConfig.GetPushTimeout())).To(Exit(0))

			//Find the app GUID
			appGUID = GetAppGUID(SSOClientAppName, testConfig.GetPushTimeout())
			fmt.Println("appGUID=" + appGUID)
			// With the APP guid find the APP Env
			creds = GetSSOCredentials(appGUID, testConfig.GetPushTimeout())
			fmt.Println(creds)
			//Request an access token
			token = getToken(creds.ClientID, creds.ClientSecret, creds.AuthDomain)
			fmt.Println("token=" + token)
			//Use the token to access the resource

			//runPushTests(appName, appURL, "auth_time", expectedNullResponse, testConfig)

		})
	})
})

func getToken(clientID, clientSecret, uri string) string {

	body := strings.NewReader(fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=client_credentials", clientID, clientSecret))
	req, err := http.NewRequest("POST", uri+"/oauth/token", body)
	if err != nil {
		fmt.Println("Error0" + err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error1" + err.Error())
	}
	defer resp.Body.Close()
	response, err := ioutil.ReadAll(resp.Body)
	var GetResponse struct {
		Token string `json:"access_token"`
	}
	json.Unmarshal(response, &GetResponse)
	return GetResponse.Token
}

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

func GetSSOCredentials(appGUID string, timeout time.Duration) OauthCredential {
	session := cf.Cf("curl", fmt.Sprintf("/v3/apps/%s/env", appGUID))
	bytes := session.Wait(timeout).Out.Contents()

	type Instance struct {
		Credential OauthCredential `json:"credentials"`
	}
	type IdentityObject struct {
		Instances []Instance `json:"p-identity"`
	}
	type SystemEnvObject struct {
		Identity IdentityObject `json:"VCAP_SERVICES"`
	}
	var GetResponse struct {
		SystemEnv SystemEnvObject `json:"system_env_json"`
	}
	err := json.Unmarshal(bytes, &GetResponse)
	Expect(err).ToNot(HaveOccurred())

	if len(GetResponse.SystemEnv.Identity.Instances) == 0 {
		Fail("No service found for response")
	}
	return GetResponse.SystemEnv.Identity.Instances[0].Credential
}

func GetAppGUID(appName string, timeout time.Duration) string {
	session := cf.Cf("curl", fmt.Sprintf("/v3/apps?names=%s", appName))
	bytes := session.Wait(timeout).Out.Contents()
	type resource struct {
		GUID string `json:"guid"`
	}
	var GetResponse struct {
		Resources []resource `json:"resources"`
	}
	err := json.Unmarshal(bytes, &GetResponse)
	Expect(err).ToNot(HaveOccurred())

	if len(GetResponse.Resources) == 0 {
		Fail("No guid found for response")
	}
	return GetResponse.Resources[0].GUID
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
