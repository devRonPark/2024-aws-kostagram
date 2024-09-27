import { useAuth } from "../../hooks/useAuth";
import NotFound from "./NotFound";

// 접근 제어용 컴포넌트
const AccessControl = ({ children, roleList }) => {
    const { userInfo } = useAuth();
    
    const role = userInfo.role || "none";

    if (roleList.includes(role)) {
        return children;
    } else {
        return <NotFound />
    }
}

export default AccessControl;