package main

import (
	"crypto/hmac"
	"fmt"
	"net/http"
)

type User struct {
	Id        string
	AddressId string
}

const VerifyMessage = "verified"

func Verify(message, sig string) bool {
	return hmac.Equal([]byte(sig), []byte(Sign(message)))
}

func main() {
	// 서버 생성
	s := NewServer()

	s.HandleFunc("GET", "/", func(c *Context) {
		fmt.Fprintln(c.ResponseWriter, "welcome!")
	})

	s.HandleFunc("GET", "/login", func(c *Context) {
		// "login.html" 렌더링
		c.RenderTemplate("/public/login.html", map[string]interface{}{"message": "로그인이 필요합니다"})
	})

	s.HandleFunc("POST", "/login", func(c *Context) {
		// 로그인 정보를 확인하여 쿠키에 인증 토큰 값을 기록
		if CheckLogin(c.Params["username"].(string), c.Params["password"].(string)) {
			http.SetCookie(c.ResponseWriter, &http.Cookie{
				Name:  "X_AUTH",
				Value: Sign(VerifyMessage),
				Path:  "/",
			})
			fmt.Println("im here")
			c.Redirect("/")
		}
		// id와 password가 맞지 않으면 다시 "/login" 페이지 렌더링
		c.RenderTemplate("/public/login.html", map[string]interface{}{"message": "id 또는 password가 일치하지 않습니다"})
	})

	// 8080 포트로 웹 서버 구동
	s.Run(":8080")

}
