import { Avatar, Card, CardContent, CardHeader, CardMedia, IconButton, Typography, useTheme } from "@mui/material";
import { useNavigate } from "react-router-dom";
import SaveIcon from '@mui/icons-material/Save';

const PostCard = ({ post }) => {
    const navigate = useNavigate();

    const theme = useTheme();

    const handleDownload = (e) => {
        e.stopPropagation();
        window.location.href = `${process.env.REACT_APP_REST_SERVER}/post/download/${post.image.id}`
    }
    return ( 
        <Card sx={{ maxWidth: 345, cursor: "pointer" }} onClick={() => navigate(`/post/${post.id}`)}>
            <CardHeader
                avatar={
                    <Avatar sx={{ bgcolor: theme.palette.main.main }}>
                        {post.id}
                    </Avatar>
                }
                title={post.title}
                subheader={post.createdAt}
                action={
                    post.image &&
                        <IconButton onClick={(e) => handleDownload(e)}>
                            <SaveIcon />
                        </IconButton>
                }
            />
            
            {/* <CardMedia
                component="img"
                height="194"
                image=""
                alt="게시글 이미지"
            />
            <CardContent>
                <Typography gutterBottom sx={{ color: 'text.secondary', fontSize: 12 }}>
                    {post.author.name} - {post.author.email}
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    {post.content}
                </Typography>
            </CardContent> */}
        </Card>
    );
}
 
export default PostCard;