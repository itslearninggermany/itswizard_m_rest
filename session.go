package itswizard_m_rest

import (
	"encoding/json"
	"errors"
	"io/ioutil"
)

type RestSession struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

/*
Get a new Request
*/
func NewSession(endpoint, username, password string) (session RestSession, err error) {
	status, body, _, err := HttpRequest("", "POST", endpoint, "", username, password, false)
	if err != nil {
		return session, err
	}
	if status != "200 OK" {
		return session, errors.New("Status: " + status + "Body: " + string(body))
	}

	var responseStruct AuthentificationResponse
	err = json.Unmarshal(body, &responseStruct)
	if err != nil {
		return session, errors.New("Error: " + err.Error() + "Status: " + status + "Body: " + string(body))
	}

	session.Token = responseStruct.Message.Jwt
	//	session.token = "pPAGRyh8B-UCi-m7D5QSevDeRrZsmXGY1bjKPGoOiPmH7ffxXXw_DedA62Zyu6oraaoTR79LdGQiQJS1IdNwvMA0xtWq5Y9jlgLLyTvzy25fdqzDqHnUlPi8kfVywMcesOQBrKArlHbqkt1RSEcXtqGC-jfG9In4Jzz0yeFKKZgDVN_DxLZWWa54u6F2Fy_Mkr6gpOQcSvJDtVU6fPXy2xS8RnnT6t_3wfxD0erG6NnGmxl118WfC-iCLRPFvJWPKbuCrSowfZP5m9edy7ggQ91mGC3RcY5Rnmdfqi0L5drNeq2hHJM6QoxNPuzcoWTlSpCVrEicVur8VlJla9-VHKP4xhWxHAS0i_0zqCIRnYBnDkIh25FAy3ieLUTZ3kh63kiqvAZHTOIPE-baUe1D54g6bMW8_kd9B0ZopvHaBzckijtL0rnBDdUpAMXLtzItgkxNzHCu2MvIAv1dQo8NT7NT81yi8nu-JOM6idxHIvzxjxtQsAQAyaUHYU_RQCaAlX7uRe_cE3A_EeYp-AtryjFzr9x6eqSi0_CnCU-hQwGjfFpHc3qaxzjYoMOABr6HiNVNSao9UZM28NCK2EakcTD52woQNcXg2tpDYGxMzpk3ZdOWLSP9VNs4CTukBPkwVmAY5MPZEwOrPts7vmlEsRbkaKv4apMv99IBDDHTZEH4BKqlCeBE_NgD52v-tVxao6xUxF9Jv5-cKQzP42pl9veQE9yCy5ahLvthMH9j_wEj6Gil0jnzvY4CWakD1HJKIbXonN7TsqD-NToSpP3POfyBy8Rhm5puVP___hsi6HOapbte81cC5acS1wm9Xho1RTEkYxnqLaES3OF6y1JYLxFhXZdE9APSrOtRYvHYVJAf42O-m0eN9n0FS-OH9vXZqLayjRCHqcCRm1i_eLpjozpHxz-QC1C_NctrBO0xYnww4dlsA1AX98qO_S1enb8Owo2A92K5BWHcI6es3Ul-Tk2kW_G2p8iHkYG5H05Ll3le7KysIrRzEYqgOJ3iFEcM5GuWxE93PDoRRvzbP-fSa_fcgi_upiGq5FXXoA2G7TG8v07WPzzKYXAUuhA9hIY="
	//	session.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBZG1pbiI6ZmFsc2UsIkF1dGhlbnRpY2F0ZWQiOnRydWUsIkVtYWlsIjoidGhvbWFzQG1mYXNmLmRlIiwiRmlyc3RBdXRoZW50aWNhdGlvbiI6dHJ1ZSwiRmlyc3RuYW1lIjoic3VwcG9ydCIsIklQIjoiMTcyLjMxLjE4LjE5MCIsIkluZm9ybWF0aW9uIjoiLS0iLCJJbnN0aXR1dGlvbiI6IlNjaHVsZW4gZGVyIExhbmRlc2hhdXB0c3RhZHQgRMO8c3NlbGRvcmYiLCJJbnN0aXR1dGlvbklEIjoyMywiTGFzdG5hbWUiOiIxMDAzNjUiLCJNb2JpbGUiOiI0OTE1MjI1NSIsIk9yZ2FuaXNhdGlvbklEIjoxMzIsIlNjaG9vbCI6IjEwMDM2NSBWb2xrZXIgUm9zaW4gU2NodWxlIiwiVHdvRmFjIjpmYWxzZSwiVXNlcklEIjoxMjgsIlVzZXJuYW1lIjoiMTAwMzY1IiwiZXhwIjoxNTg3NzMyMjQxLCJpYXQiOjE1ODc3Mjg2NDF9.VThUmV3KuUsjIioRaMB7KRBsAe7Hi5TvT2ykcxpNvrc"
	session.Endpoint = endpoint
	return session, nil
}

func LoadSession(filepath, username, password, endpoint string) (RestSession, error) {
	restSession := RestSession{}
	setupByte, err := ioutil.ReadFile(filepath)
	if err != nil {
		return restSession, err
	}
	err = json.Unmarshal(setupByte, &restSession)
	if err != nil {
		return restSession, err
	}
	//Update VersionK
	restSession.Endpoint = endpoint
	//TODO LATER!!
	/*
		valid, err := restSession.TokenValid(proxy)
		if err != nil {
			return restSession, err
		}
		if !valid {
			restSession, err = NewSession(restSession.Endpoint, username, password)
			if err != nil {
				return restSession, err
			}
		}
	*/
	return restSession, nil
}

func (p *RestSession) SaveSession(filepath string) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath, b, 600)
}
