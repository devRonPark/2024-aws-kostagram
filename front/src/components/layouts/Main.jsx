import { Grid2 } from "@mui/material";

const Main = ({ children }) => {
    return (
        <Grid2
            container
            my={3}
            spacing={1}
            direction={"column"}
            alignItems={"center"}
        >
            { children }
        </Grid2>
    );
}
 
export default Main;