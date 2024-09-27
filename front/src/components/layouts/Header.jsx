import { alpha, AppBar, Box, Button, IconButton, InputBase, List, ListItem, ListItemButton, ListItemText, styled, Toolbar } from "@mui/material";
import MenuIcon from "@mui/icons-material/Menu";
import { FaApple } from "react-icons/fa6";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Drawer from "./Drawer";
import SearchIcon from '@mui/icons-material/Search';
import { postAPI } from "../../api/services/post";
import { useAuth } from "../../hooks/useAuth";

const Header = () => {
    const { userInfo, tokenCheck, logout } = useAuth();
 
    let allMenu = [
        {path: '/user', name: '회원 관리', auth: ["ROLE_ADMIN"]},
        {path: '/favorite', name: '즐겨찾기', auth: ["ROLE_ADMIN", "ROLE_USER"]},
        {path: '/post', name: '게시물', auth : ["ROLE_ADMIN", "ROLE_USER", "none"]},
        {path: '/signup', name: '회원가입', auth: ["none"]},
        {path: '/login', name: '로그인', auth: ["none"]},
        {path: '/logout', name: '로그아웃', auth: ["ROLE_ADMIN", "ROLE_USER"]},
        {path: '/search', name: '검색', auth : ["ROLE_ADMIN", "ROLE_USER", "none"]},
    ]

    const [menu, setMenu] = useState([]);

    useEffect(() => {
        // 만약에 브라우저 토큰이 유효하면
        const role = tokenCheck();
        if (role) {
            // 권한에 맞는 메뉴 설정
            setMenu(allMenu.filter(m => m.auth.includes(role)));
        // 그렇지 않으면
        } else {
            // none 메뉴 설정
            setMenu(allMenu.filter(m => m.auth.includes("none")));
        }
    }, [userInfo]);

    const [menuOpen, setMenuOpen] = useState(false);

    const navigate = useNavigate();

    const toggleDrawer = () => {
        setMenuOpen(prev => !prev);
    }

    return (
        <>
        <AppBar position="static" color="main">
            <Toolbar sx={{justifyContent: 'space-between'}}>
                <IconButton
                    color='font'
                    sx={{display: {sm: 'none'}}}
                    onClick={toggleDrawer}
                >
                    <MenuIcon />
                </IconButton>
                <Box sx={{display: {xs: 'none', sm: 'block'}, cursor: 'pointer'}}>
                    <FaApple onClick={()=> navigate('/')} />
                </Box>

                <Box sx={{display: {xs: 'none', sm: 'block'}}}>
                    {
                        menu.map((m, idx) => {
                            if (m.path === "/search") {
                                return <MySearch key={idx} />;
                            }
                            if (m.path === "/logout") {
                                return (
                                    <Button
                                        key={idx}
                                        color='font'
                                        onClick={() => logout(() => navigate("/login"))}
                                    >
                                        {m.name}
                                    </Button>
                                )
                            }
                            return (
                                <Button
                                    key={idx}
                                    color='font'
                                    onClick={() => navigate(m.path)}
                                >
                                    {m.name}
                                </Button>
                            )
                        })
                    }
                </Box>
            </Toolbar>
        </AppBar>

        {/* Drawer 추가 */}
        <Drawer menuOpen={menuOpen} toggleDrawer={toggleDrawer}>
            <List>
                {
                    menu.map((m, idx) => (
                        <ListItem key={idx} disablePadding>
                            <ListItemButton onClick={() => navigate(m.path)}>
                                <ListItemText primary={m.name} />
                            </ListItemButton>
                        </ListItem>
                    ))
                }
            </List>
        </Drawer>
        </>
    );
}

const MySearch = () => {
    const navigate = useNavigate();
    const [keyword, setKeyword] = useState("");
    const handleSearch = (e) => {
        if (e.key === "Enter") {
            // alert(`${keyword} 검색`);
            // http://localhost:8080/post/search?keyword=검색어
            postSearch(keyword);
        }
    }

    const postSearch = async (keyword) => {
        try {
            const res = await postAPI.searchPost(keyword);
            navigate("/search", { state : res.data });
        } catch (error) {
            console.error(error);
        }
    } 

    return (
        <Search>
            <SearchIconWrapper>
                <SearchIcon />
            </SearchIconWrapper>
            <StyledInputBase
                placeholder="Search…"
                value={keyword}
                onKeyDown={(e) => handleSearch(e)}
                onChange={(e) => setKeyword(e.target.value)}
            />
        </Search>
    )
}

const Search = styled('div')(({ theme }) => ({
    display: "inline-block",
    position: 'relative',
    borderRadius: theme.shape.borderRadius,
    backgroundColor: alpha(theme.palette.common.white, 0.15),
    '&:hover': {
      backgroundColor: alpha(theme.palette.common.white, 0.25),
    },
    marginLeft: 0,
    width: '100%',
    [theme.breakpoints.up('sm')]: {
      marginLeft: theme.spacing(1),
      width: 'auto',
    },
  }));
  
const SearchIconWrapper = styled('div')(({ theme }) => ({
    padding: theme.spacing(0, 2),
    height: '100%',
    position: 'absolute',
    pointerEvents: 'none',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  }));
  
const StyledInputBase = styled(InputBase)(({ theme }) => ({
    color: 'inherit',
    width: '100%',
    '& .MuiInputBase-input': {
      padding: theme.spacing(1, 1, 1, 0),
      // vertical padding + font size from searchIcon
      paddingLeft: `calc(1em + ${theme.spacing(4)})`,
      transition: theme.transitions.create('width'),
      [theme.breakpoints.up('sm')]: {
        width: '12ch',
        '&:focus': {
          width: '20ch',
        },
      },
    },
  }));
  

export default Header;