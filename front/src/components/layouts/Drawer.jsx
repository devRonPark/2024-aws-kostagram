import { Box, Divider, Drawer as MuiDrawer, Typography } from "@mui/material";

const Drawer = ({ children, menuOpen, toggleDrawer }) => {
    return ( 
        <nav>
            <MuiDrawer
                open={menuOpen}
                onClose={toggleDrawer} 
                anchor="left"
                sx={{ 
                    display: { xs: 'block', sm : 'none' },
                    '& .MuiDrawer-paper' : { boxSizing : 'border-box', width: '50%' } 
                }}
            >
                <Box onClick={toggleDrawer} sx={{ textAlign: 'center' }}>
                    <Typography variant="h6" sx={{ my: 2}}>
                        블로그
                    </Typography>
                </Box>
                <Divider />
                {children}
            </MuiDrawer>
        </nav>
     );
}
 
export default Drawer;