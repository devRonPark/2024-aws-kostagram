import { useState } from "react";
import { userAPI } from "../api/services/user";
import { jwtDecode } from 'jwt-decode';
import { getCookie, removeCookie, setCookie } from "../utils/cookieUtil";

export const useProvideAuth = () => {
    const [userInfo, setUserInfo] = useState({});

    const refreshUserInfo = () => {
        const token = getCookie("accessToken");
        if (token) {
            const jwtPayload = jwtDecode(token);
            setUserInfo({
                id: jwtPayload.id,
                email: jwtPayload.sub,
                role: jwtPayload.role
            });
        }
    }

    const login = async(data, successCallback = null) => {
        try {
            const res = await userAPI.login(data);
            if (res.status === 200) {
                const token = res.data.accessToken;
                // localStorage.setItem("token", token);
                setCookie('accessToken', token, { path: '/' });
                refreshUserInfo();
                if(successCallback) successCallback();
            }
        } catch (error) {
            console.error(error);
        }
    }

    const logout = (callback = null) => {
        // localStorage.removeItem("token");
        removeCookie("accessToken");
        setUserInfo({});
        if(callback) callback();
    }

    const tokenCheck = () => {
        // const token = localStorage.getItem("token");
        const token = getCookie("accessToken");
        if (token) {
            const jwtPayload = jwtDecode(token);
            return jwtPayload.role;
        } else {
            return false;
        }
    }

    return {
        userInfo,
        refreshUserInfo,
        tokenCheck,
        login,
        logout
    }
}