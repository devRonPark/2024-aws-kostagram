import { Button, Divider, Grid2 } from "@mui/material"
import axios from "axios";
import { useEffect } from "react";
import { useState } from "react";
import PostCard from "./PostCard";
import { useLocation, useNavigate } from "react-router-dom";
import { postAPI } from "../../api/services/post";
import { useAuth } from "../../hooks/useAuth";

const Post = () => {
    const { state } = useLocation();
    const { userInfo } = useAuth();
    const navigate = useNavigate();
    const [postList, setPostList] = useState([]);

    const getPostList = async() => {
        if (state) {
            setPostList(state);
        } else {
            try {
                const res = await postAPI.getPostList();
                const data = res.data;
                setPostList(data);
            } catch (error) {
                console.error(error);
                navigate("/error", {state: error.message});
            }
        }    
    }

    useEffect(() => {
        getPostList();
    }, [state]);

    return (
        <>
            <h1>포스트</h1>
            {
                userInfo &&
                <>
                    <Button variant="contained" color="main" onClick={() => navigate("/post/write")}>글쓰기</Button>
                    <Divider />
                </>
            }
            <Grid2 container direction={"column"} spacing={2}>
                {
                    postList.map(post => (
                        <PostCard key={post.id} post={post}></PostCard>
                    ))
                }
            </Grid2>
        </>
    );
}
 
export default Post;