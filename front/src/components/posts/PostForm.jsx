import { Button, Grid2, TextField, Typography } from "@mui/material";
import axios from "axios";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useNavigate, useParams } from "react-router-dom";
import { postAPI } from "../../api/services/post";

const PostForm = () => {
    const { register, handleSubmit, watch, formState: { errors }, setValue } = useForm();
    const navigate = useNavigate();

    const { postId } = useParams();
    
    // 요청을 보내야지 axios (${process.env.REACT_APP_REST_SERVER}/post/id)
    const getPost = async () => {
        try {
            const res = await postAPI.getPost(postId);
            const data = res.data;
            setValue("title", data.title);
            setValue("content", data.content);
        } catch (error) {
            navigate("/error", {state: error.message});
        }
    }

    useEffect(() => {
        if (postId) {
            getPost();
        }
    }, []);

    const onSubmit = async (data) => {
        data.image = data.image[0]; // 추가한 이미지 하나를 보냄
        data.authorId = 1; // 로그인 기능 추가 전까지 임의로 작성

        const formData = new FormData();
        Object.keys(data).forEach(key => {
            formData.append(key, data[key]);
        });

        try {
            if (postId) {
                formData.append("id", postId);
                const res = await postAPI.modifyPost(formData);
            } else {
                const res = await postAPI.writePost(formData);
            }
            // 정상적인 응답이면 -> 게시글 목록으로 보내주자
            navigate("/post");
        } catch (error) {
            // 비정상이면 -> 에러 페이지 가자
            navigate("/error", {state: error.message});
        }
    }

    // watch("이름") -> 해당 입력 "이름"의 값을 가져온다.
    // console.log(watch("name"))

    return (
        <>
            {/* "handleSubmit" 함수는 onSubmit 동작 전에 입력값에 대한 유효값 검증(validation)한다.  */ }
            <form onSubmit={handleSubmit(onSubmit)}>
                <Grid2 container direction={"column"} spacing={3} sx={{ width : {xs: '250px', sm: '500px'} }}>
                    {/* ...register("이름") -> 값이 전달된다. */}
                    {/* 필수값, 유효성 검증 등을 추가할 수 있다. */}
                    {/* 제목 (필수, 50자 이내) */}
                    <TextField 
                        variant="outlined"
                        label="제목"
                        error={errors.title ? true : false}
                        helperText={errors.title && "제목은 필수값이며, 50자 이내로 작성해야 합니다."}
                        {...register("title", { required: true, maxLength: 50})}
                        fullWidth
                    />
                    
                    {/* 내용 (필수) */}
                    <TextField
                        id="outlined-multiline-static"
                        label="내용"
                        multiline
                        rows={4}
                        error={errors.content ? true : false}
                        helperText={errors.content && "내용은 필수값입니다"}
                        {...register("content", { required: true })}
                    />
                    {/* 이미지 파일 (선택) */}                    
                    <TextField 
                        type="file"
                        label="이미지 파일"
                        {...register("image", { required: false })}
                        slotProps={{ htmlInput : {"accept": "image/*"} }}
                    />
                    {/* 비밀번호 (필수, 영어+숫자 8자리 이상) */}                    
                    <TextField
                        id="outlined-password-input"
                        label="비밀번호"
                        type="password"
                        autoComplete="current-password"
                        error={errors.password ? true : false}
                        helperText={errors.password && "비밀번호는 필수값이며, 영어와 숫자를 포함해 8자리 이상 20자리 이하로 작성해주세요."}
                        {...register("password", { required: true, pattern: /^(?=.*[a-zA-Z])(?=.*[0-9]).{8,20}$/ })}
                        fullWidth
                    />
                    <Button fullWidth type="submit" variant="outlined" color="main">제출</Button>
                </Grid2>
                
            </form>
        </>
    );
}
 
export default PostForm;