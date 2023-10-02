package itswizard_m_rest

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/itslearninggermany/itswizard_m_basic"
	"github.com/jinzhu/gorm"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var proxy string = "http_proxy"

/*
Databasestructure for univention
*/
type UniventionUploads struct {
	gorm.Model
	UserID         uint
	OrganisationID uint
	InstitutionID  uint
	Filename       string
	Data           string `gorm:"type:LONGTEXT"`
	Success        bool
}

type UniventionUploadsGroup struct {
	gorm.Model
	UserID         uint
	OrganisationID uint
	InstitutionID  uint
	Filename       string
	Data           string `gorm:"type:LONGTEXT"`
	Success        bool
	Errorstring    string `gorm:"type:MEDIUMTEXT"`
	Error          bool
}

type UniventionUploadsPerson struct {
	gorm.Model
	UserID         uint
	OrganisationID uint
	InstitutionID  uint
	Filename       string
	Data           string `gorm:"type:LONGTEXT"`
	Success        bool
	Errorstring    string `gorm:"type:MEDIUMTEXT"`
	Error          bool
}

type UniventionAes struct {
	gorm.Model
	UserID         uint `gorm:"unique"`
	OrganisationID uint
	InstitutionID  uint
	AesKey         string
}

type SendDataFromUniventionRequest struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

type SendAesKeyFromUniventionRequest struct {
	Username string `json:"username"`
	Key      []byte `json:"key"`
}

type SendDataFromUniventionResponse struct {
	Error   interface{} `json:"error"`
	Message struct {
		Data        string `json:"data"`
		Filename    string `json:"filename"`
		Information string `json:"information"`
	} `json:"message"`
}

const SendDataFromUnivnetionApi = "/univention/data"
const SendLogFromUnivnetionApi = "/univention/log"
const SendAesKeyFromUnivnetionApi = "/univention/aeskey"
const SendCsvData = "/csv/send"
const PersonIdentifierUpdate = "/PersonIdentifierUpdate"

/*
Send AES-Key to itslearning
*/
func (p *RestSession) SendAesKeyFromUnivention(aesKeyAsString string) (string, error) {
	//SEND DATA
	status, body, _, err := HttpRequest(aesKeyAsString, "POST", p.Endpoint+SendAesKeyFromUnivnetionApi, p.Token, "", "", false)
	//CHECK
	if err != nil {
		return "", err
	}
	if status != "200 OK" {
		return "", errors.New(status)
	}
	if string(body) == "Token is expired" {
		return string(body), errors.New(string(body))
	}
	if string(body) == "AESKey stored" {
		return string(body), nil
	}
	if string(body) == "AESKey updated" {
		return string(body), nil
	}

	return "", errors.New(string(body))
}

/*
Send JSON-Files with User and Groups
*/
func (p *RestSession) SendDataFromUnivention(filename string, data []byte) (sendData SendDataFromUniventionResponse, err error) {
	//Prepare DATA
	o := SendDataFromUniventionRequest{
		Filename: filename,
		Content:  string(data),
	}

	b, err := json.Marshal(o)
	if err != nil {
		return sendData, err
	}
	//SEND DATA
	status, body, _, err := HttpRequest(string(b), "POST", p.Endpoint+SendDataFromUnivnetionApi, p.Token, "", "", false)

	//CHECK
	if err != nil {
		return sendData, err
	}
	if status != "200 OK" {
		return sendData, errors.New(status)
	}
	if string(body) == "Token is expired" {
		sendData.Error = errors.New(string(body))
	} else {
		err := json.Unmarshal(body, &sendData)
		if err != nil {
			return sendData, err
		}
	}

	return sendData, err
}

/*
Send Logfile from UCS-System
*/
func (p *RestSession) SendLogFromUnivention(filename string, data []byte) error {
	o := SendDataFromUniventionRequest{
		Filename: filename,
		Content:  string(data),
	}

	b, err := json.Marshal(o)
	if err != nil {
		return err
	}

	status, body, _, err := HttpRequest(string(b), "POST", p.Endpoint+SendLogFromUnivnetionApi, p.Token, "", "", false)
	if err != nil {
		return err
	}
	if status != "200 OK" {
		return errors.New(status)
	}
	if string(body) == "Token is expired" {
		return errors.New(string(body))
	}
	log.Println(string(body))
	return err
}

func makeAuthorisation(username, password string) (string, error) {
	b, err := json.Marshal(Login{
		Username: username,
		Password: password,
	})
	if err != nil {
		log.Println("Problem creating header: ", err)
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(b)
	return encoded, err
}

type Proxy struct {
	proxy *url.URL
	err   error
}

func (p *Proxy) checkProxy() bool {
	pr, exist := os.LookupEnv(strings.ToLower(proxy))
	if !exist {
		pr, _ = os.LookupEnv(strings.ToUpper(proxy))
	}
	if pr != "" {
		log.Println("Proxy exist")
		exist = true
	} else {
		log.Println("There is no proxy")
		exist = false
	}
	proxy, err := url.Parse(pr)
	p.proxy = proxy
	p.err = err
	return exist
}
func HttpRequest(content, method, url, authtoken, username, passwort string, setTSL bool) (status string, body []byte, header http.Header, err error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(content)))
	if err != nil {
		log.Println("Problem by creating request: ", err)
		return
	}

	if username != "" && passwort != "" {
		auth, err := makeAuthorisation(username, passwort)
		if err != nil {
			log.Println("Error by creating Authorisation:", err)
			return status, body, header, err
		}
		req.Header.Set("Authorization", auth)
		log.Println("Authorization was set.")
	}
	if authtoken != "" {
		req.Header.Set("Authorization", authtoken)
		log.Println("Authorization was set.")
	}

	req.Header.Set("Content-Type", "application/file")

	tr := &http.Transport{}

	//Proxy
	proxy := Proxy{}
	if proxy.checkProxy() {
		tr.Proxy = http.ProxyURL(proxy.proxy)
		log.Println("Proxy added to transport")
	} else {
		if proxy.err != nil {
			log.Println("Error by getting Proxy: ", proxy.err)
			err = proxy.err
			return
		}
	}

	if setTSL {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		log.Println("TLS")
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()
	body, _ = ioutil.ReadAll(resp.Body)
	status = resp.Status
	header = resp.Header
	return
}

/*
Send CSV-Files with User and Groups
*/
type CsvRquestFull struct {
	CsvRequest []CsvReq `json:"CsvRequest"`
}

type CsvReq struct {
	Filename  string `json:"Filename"`
	Seperator string `json:"Seperator"`
	Content   string `json:"Content"`
}

type CsVDataResponse struct {
	Error   interface{} `json:"error"`
	Message struct {
		Information string `json:"information"`
	} `json:"message"`
}

func (p *RestSession) SendCSV(CsvRequest []CsvReq) (sendData CsVDataResponse, err error) {
	o := CsvRquestFull{CsvRequest: CsvRequest}

	b, err := json.Marshal(o)
	if err != nil {
		return sendData, err
	}
	//SEND DATA
	status, body, _, err := HttpRequest(string(b), "POST", p.Endpoint+SendCsvData, p.Token, "", "", false)

	//CHECK
	if err != nil {
		return sendData, err
	}
	if status != "200 OK" {
		return sendData, errors.New(status)
	}
	if string(body) == "Token is expired" {
		sendData.Error = errors.New(string(body))
	} else {
		err := json.Unmarshal(body, &sendData)
		if err != nil {
			return sendData, err
		}
	}

	return sendData, err
}

type PersonIdentifierUpdateRquestFull struct {
	OldIdentifier string `json:"OldIdentifier"`
	NewIdentifier string `json:"NewIdentifier"`
	UserName      string `json:"UserName"`
	FirsNname     string `json:"FirsNname"`
	LastName      string `json:"LastName"`
	Email         string `json:"Email"`
	Profile       string `json:"Profile"`
	Phone         string `json:"Phone"`
	Mobile        string `json:"Mobile"`
	Street1       string `json:"Street1"`
	Street2       string `json:"Street2"`
	Postcode      string `json:"Postcode"`
	City          string `json:"City"`
}

type PersonIdentifierUpdateDataResponse struct {
	Error   interface{} `json:"error"`
	Message struct {
		Information string `json:"information"`
	} `json:"message"`
}

func (p *RestSession) SendPersonIdentifyerUpdate(oldIdentifyer string, newPerson itswizard_m_basic.Person) (sendData CsVDataResponse, err error) {
	o := PersonIdentifierUpdateRquestFull{
		OldIdentifier: oldIdentifyer,
		NewIdentifier: newPerson.PersonSyncKey,
		UserName:      newPerson.Username,
		FirsNname:     newPerson.FirstName,
		LastName:      newPerson.LastName,
		Email:         newPerson.Email,
		Profile:       newPerson.Profile,
		Phone:         newPerson.Phone,
		Mobile:        newPerson.Mobile,
		Street1:       newPerson.Street1,
		Street2:       newPerson.Street2,
		Postcode:      newPerson.Postcode,
		City:          newPerson.City,
	}

	b, err := json.Marshal(o)
	if err != nil {
		return sendData, err
	}
	//SEND DATA
	status, body, _, err := HttpRequest(string(b), "POST", p.Endpoint+PersonIdentifierUpdate, p.Token, "", "", false)

	//CHECK
	if err != nil {
		return sendData, err
	}
	if status != "200 OK" {
		return sendData, errors.New(status)
	}
	if string(body) == "Token is expired" {
		sendData.Error = errors.New(string(body))
	} else {
		err := json.Unmarshal(body, &sendData)
		if err != nil {
			return sendData, err
		}
	}

	return sendData, err
}
