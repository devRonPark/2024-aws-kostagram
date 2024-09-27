import { BrowserRouter } from "react-router-dom";
import Header from "./Header";
import Main from "./Main";
import { useAuth } from "../../hooks/useAuth";
import { useEffect } from "react";

const Layout = ({ children }) => {
    const { refreshUserInfo } = useAuth();
    
    useEffect(() => {
        refreshUserInfo();
    }, []);

    return (
        <BrowserRouter>
            <Header />
            <Main>
                { children }
            </Main>
        </BrowserRouter>
    );
}
 
export default Layout;