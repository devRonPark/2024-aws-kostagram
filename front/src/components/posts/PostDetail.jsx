import axios from "axios";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Avatar, Button, Card, CardActions, CardContent, CardHeader, CardMedia, Typography, useTheme } from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import Swal from "sweetalert2";
import { postAPI } from "../../api/services/post";
import { useAuth } from "../../hooks/useAuth";

const PostDetail = () => {
    const { userInfo } = useAuth();

    // id 값 가져오기
    const {postId} = useParams();
    const navigate = useNavigate();
    const theme = useTheme();
    const [post, setPost] = useState();

    // 요청을 보내야지 axios (${process.env.REACT_APP_REST_SERVER}/post/id)
    const getPost = async () => {
        try {
            const res = await postAPI.getPost(postId);
            const data = res.data;
            setPost(data);
        } catch (error) {
            navigate("/error", {state: error.message});
        }
    }

    // 가져온 정보를 예쁘게 화면에 뿌려주자
    useEffect(() => {
        getPost();    
    }, []);
    
    const handleDelete = async () => {
        const result = await Swal.fire({
            title: "삭제를 원하세요?",
            input: "password",
            inputPlaceholder: "비밀번호를 입력하세요",
            inputAttributes: {
                maxlength: "20",
                autocapitalize: "off",
                autocorrect: "off"
            },
            showCancelButton: true,
            showCloseButton: true
        });
        // if (result.dismiss === "close") {
        //     console.log("닫았네");
        // } else if (result.dismiss === "cancel") {
        //     console.log("취소했네");
        // }
        const password = result.value;
        if (password) {
            const authorId = 1; // 로그인 기능 전까지 임시 작성자 아이디
            try {
                const res = await postAPI.deletePost(post.id, password, authorId);
                Swal.fire({
                    title: "잘했어요!",
                    text: `${post.id}번 게시물이 삭제되었습니다.`,
                    icon: "success"
                });
                navigate("/post");
            } catch (error) {
                navigate("/error", {state: error.message});
            }
        }
    }

    return (
        <>
            <h1>게시물 상세정보</h1>
            {post && 
                <Card sx={{ width : {xs: '250px', sm: '500px', md: '800px'} }} >
                    <CardHeader
                        avatar={
                            <Avatar sx={{ bgcolor: theme.palette.main.main }}>
                                {post.id}
                            </Avatar>
                        }
                        title={post.title}
                        subheader={post.createdAt}
                    />
                    {
                        post.image && <CardMedia
                            component="img"
                            image={`${process.env.REACT_APP_SERVER}/img/${post.image.saved}`}
                            alt="게시글 이미지"
                        />
                    }
                    <CardContent>
                        <Typography gutterBottom sx={{ color: 'text.secondary', fontSize: 12 }}>
                            {post.author.name} - {post.author.email}
                        </Typography>
                        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                            {post.content}
                        </Typography>
                    </CardContent>
                    {
                        userInfo &&
                        <CardActions>
                            <Button
                                variant="contained"
                                color="bg2"
                                size="small"
                                startIcon={<EditIcon />}
                                onClick={() => navigate(`/post/modify/${post.id}`)}
                            >
                                수정
                            </Button>
                            <Button
                                variant="contained"
                                color="sub"
                                size="small"
                                startIcon={<DeleteIcon/>}
                                onClick={handleDelete}
                            >
                                삭제
                            </Button>
                        </CardActions>
                    }
                </Card>
            }
        </>
    );
}

export default PostDetail;