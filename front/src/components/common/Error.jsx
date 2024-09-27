import { useLocation } from "react-router-dom";

const Error = () => {
    const { state } = useLocation(); 
    return (
        <>
            에러
            <div>
                { state }
            </div>
        </>
    );
}
 
export default Error;