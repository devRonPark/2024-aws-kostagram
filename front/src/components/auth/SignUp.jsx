import { Box, Button, Divider, FormControl, FormLabel, Grid2, InputBase, Paper, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { userAPI } from "../../api/services/user";
import { useNavigate } from "react-router-dom";
import Swal from "sweetalert2";

const SignUp = () => {
    /* REACT HOOK FORM */
    const { register, formState: { errors }, handleSubmit, setValue, getValues, setError, clearErrors } = useForm();

    /* navigate */
    const navigate = useNavigate();

    /* 회원가입 */
    const onSubmit = async (data) => {        
        try {
            console.log("회원가입 로직", data);
            const res = await userAPI.addUser(data);
            if (res.status === 201) {
                // 회원가입 성공 시 메시지와 함께 메인으로 이동
                Swal.fire({
                    html: "가입에 성공했습니다.",
                    timer: 1500,
                    timerProgressBar: true,
                }).then(navigate("/"));
            }
        } catch (error) {
            console.error(error);
            navigate("/error", {state: error.message});
        }
    }
    
    /* 이메일 중복 확인 여부를 체크하기 위한 state*/
    const [isNotDuplicate, setIsNotDuplicate] = useState(false);

    /* 중복 확인 결과를 통한 색상 변경 state */
    const [emailColor, setEmailColor] = useState("main");
    
    /* 이메일 중복 확인 */
    const emailCheck = async() => {
        console.log("이메일 체크");
        const email = getValues("email");
        const regExp = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        
        // 이메일 정규식 체크하여, 통과하면 중복체크
        if(regExp.test(email)) {
            // 중복체크
            const res = await userAPI.emailCheck(email);
            if (res.data) {
                // 중복체크 성공 시
                setIsNotDuplicate(true);
                setEmailColor("success");
                clearErrors("email");
            } else {
                setError("email", { type: 'custom', message: '중복된 이메일입니다.' });
            }
        } else {
            // 이메일 정규식 체크 실패 또는 중복된 이메일일 경우.
            setError("email", { type: 'custom', message: '이메일 형식에 맞지 않습니다.' });
        }
    }

    // 이메일 값이 변경되면, 중복체크 다시 할 수 있도록 설정
    const emailInputReset = () => {
        setIsNotDuplicate(false);
        setEmailColor("main")
    }

    return (
        <Paper variant="outlined">
            <Box component="form" noValidate sx={{ p: 5 }} onSubmit={handleSubmit(onSubmit)}>
                <Typography component="h1" variant="h6" gutterBottom>회원가입을 진행합니다.</Typography>
                <Divider sx={{ my: 2 }} />
                <Stack direction={"row"} sx={{ justifyContent: "space-between", alignItems: "center"}}>
                    <TextField
                        onInput={emailInputReset}
                        label="Email address"
                        id="email"
                        name="email"
                        placeholder="your email address"
                        variant="standard"
                        margin="normal"
                        type="email"
                        focused
                        color={emailColor}
                        autoComplete="email"
                        {...register(
                            "email",
                            { 
                                required: "이메일은 필수 입력값입니다.", 
                                validate: () => isNotDuplicate ? clearErrors() : "이메일 체크를 해주세요."
                            }
                        )}
                        error={errors.email ? true : false}
                        helperText={errors.email && errors.email.message}
                    />
                    <Button
                        onClick={() => emailCheck()}
                        variant="outlined"
                        color="sub"
                    >
                        Email Check
                    </Button>
                </Stack>
                <TextField
                    label="Name"
                    id="name"
                    name="name"
                    placeholder="your name"
                    variant="standard"
                    fullWidth
                    margin="normal"
                    focused
                    color="main"
                    autoComplete="name"
                    sx={{ mb: 3 }}
                    {...register( "name", { required: "이름은 필수 입력값입니다.", } )}
                    error={errors.name ? true : false}
                    helperText={errors.name && errors.name.message}
                />
                <TextField
                    label="Password"
                    id="password"
                    name="password"
                    placeholder="your password"
                    variant="standard"
                    fullWidth
                    margin="normal"
                    type="password"
                    focused
                    color="main"
                    autoComplete="password"
                    sx={{ mb: 3 }}
                    {...register( "password",
                        { 
                            required: "비밀번호를 입력해주세요",
                            pattern: {
                                value: /^(?=.*[a-zA-Z0-9]).{6,20}$/,
                                message: "비밀번호는 문자와 숫자를 포함해 최소 6자 이상 20자 이내로 작성해주세요."
                            }
                        }
                    )}
                    error={errors.password ? true : false}
                    helperText={errors.password && errors.password.message}
                />
                <Button type="submit" variant="contained" color="sub" fullWidth>가입하기</Button>
            </Box>
        </Paper>
    );
}
 
export default SignUp;