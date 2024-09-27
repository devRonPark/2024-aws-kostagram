import { useParams } from "react-router-dom";
import { oauthAPI } from "../../api/services/oauth";
import { useEffect } from "react";
import { setCookie } from "../../utils/cookieUtil";

const OAuthLogin = () => {
    const { provider } = useParams();
    const code = new URLSearchParams(window.location.search).get("code");
    console.log("서버에 전달해야 하는 코드 값 : ", code);

    const oAuthAPI = {
        "kakao" : (code) => oauthAPI.kakaoLogin(code),
        "google" : (code) => oauthAPI.googleLogin(code)
    }
    
    const login = async () => {
      try {
        const response = await oAuthAPI[provider](code);
        if (response.status !== 200) {
          throw new Error("로그인 실패");
        } else {
          setCookie("accessToken", response.data.accessToken, { path: "/" } );
          window.location.href="/";
        }
      } catch (error) {
        console.error(error);
      }
    }

    useEffect(() => {
      login();
    }, [code]);
  
    return ( <div>로그인 처리 중~ </div>);
}

export default OAuthLogin;