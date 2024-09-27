import { Box, Button, FormControl, FormLabel, Grid2, Paper, Stack, styled, Switch, TextField, Typography } from "@mui/material";
import { useForm } from "react-hook-form";
import { favAPI } from "../../api/services/favorite";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { useEffect, useRef, useState } from "react";

const FavForm = () => {
    // const { favId } = useParams();
    const { state } = useLocation();
    const navigate = useNavigate();
    const { register, formState: { errors }, handleSubmit, setValue,  } = useForm();

    const [uploadFile, setUploadFile] = useState();
    const imgRef = useRef();
    const uploadFilePreview = () => {
        const reader = new FileReader();
        reader.readAsDataURL(imgRef.current.files[0]);
        reader.onloadend = () => {
            setUploadFile(reader.result);
        };
    };

    useEffect(() => {
        if (state) {
            state.image && setShowFileInput(false);
            setValue("title", state.title);
            setValue("url", state.url);
        }
    }, []);

    const [showFileInput, setShowFileInput] = useState(true);
    const toggleFileInput = () => {
        setShowFileInput(prev => !prev);
    }
    const onSubmit = async (data) => {
        try {
            const formData = new FormData();
            Object.keys(data).forEach(key => {
                formData.append(key, data[key]);
            });

            if (data.logo.length) {
                formData.append("image", data.logo[0]);
            } else {
                formData.delete("image");
                if (showFileInput) {
                    formData.append("deleteImage", true);
                }
            }

            if (state) {
                formData.append("id", state.id);
                const res = await favAPI.modifyFav(formData);
            } else {
                const res = await favAPI.writeFav(formData);
            }
            navigate("/favorite")
        } catch (error) {
            console.error(error);
            navigate("/error", {state: error.message});
        }
    }
    return (
        <Paper
            elevation={3}
            sx={{
                padding: 4,
                maxWidth: 600,
                margin: "auto",
                marginTop: 4,
            }}
            >
         <Box component="form" onSubmit={handleSubmit(onSubmit)} noValidate>
            <Grid2 container spacing={3}>
                <FormControl fullWidth>
                    <FormLabel htmlFor="title">사이트 이름</FormLabel>
                    <TextField
                        autoComplete="title"
                        {...register("title", { required: true })}
                        fullWidth
                        id="title"
                        placeholder="구글"
                        error={errors.title ? true : false}
                        helperText={errors.title && "사이트 이름은 필수값입니다."}
                    />
                </FormControl>
                <FormControl fullWidth>
                    <FormLabel htmlFor="url">URL</FormLabel>
                    <TextField
                        id="url"
                        fullWidth
                        {...register("url", { 
                            required: true,
                            pattern: /((?:https\:\/\/)|(?:http\:\/\/)|(?:www\.))?([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(?:\??)[a-zA-Z0-9\-\._\?\,\'\/\\\+&%\$#\=~]+)/
                        })}
                        autoComplete="url"
                        placeholder="www.google.com"
                        variant="outlined"
                        error={errors.url ? true : false}
                        helperText={errors.url && "주소 규격에 맞지 않습니다."}
                    />
                </FormControl>
                <FormControl fullWidth>
                    <FormLabel component="legend">로고 이미지</FormLabel>
                    {state?.image && (
                        <Stack
                        direction="row"
                        spacing={1}
                        sx={{ alignItems: "center", marginBottom: 1 }}
                        >
                        <Typography>변경</Typography>
                        <AntSwitch
                            defaultChecked
                            onClick={toggleFileInput}
                        />
                        <Typography>유지</Typography>
                        </Stack>
                    )}
                    {showFileInput &&
                        <>
                            <TextField
                                type="file"
                                {...register("logo")}
                                slotProps={{ htmlInput : {"accept": "image/*"}}}
                                variant="outlined"
                                inputRef={imgRef}
                                onChange={uploadFilePreview}
                            />
                        </>
                    }
                    { (!showFileInput || uploadFile) && 
                        <Box sx={{ textAlign: "center", marginTop: 2 }}>
                            <img
                                src={uploadFile ? uploadFile : `${process.env.REACT_APP_SERVER}/img/${state.image.saved}`}
                                alt="Current Logo"
                                style={{ maxWidth: "100%", maxHeight: 200 }}
                            />
                        </Box>
                    }
                </FormControl>
                <Button
                    type="submit"
                    fullWidth
                    variant="contained"
                >
                    {state ? "수정하기" : "등록하기"}
                </Button>
            </Grid2>   
        </Box>
        </Paper>
    );
}
 
const AntSwitch = styled(Switch)(({ theme }) => ({
    width: 36,
    height: 20,
    padding: 0,
    display: "flex",
    "&:active": {
      "& .MuiSwitch-thumb": {
        width: 15,
      },
      "& .MuiSwitch-switchBase.Mui-checked": {
        transform: "translateX(16px)",
      },
    },
    "& .MuiSwitch-switchBase": {
      padding: 2,
      "&.Mui-checked": {
        transform: "translateX(16px)",
        color: "#fff",
        "& + .MuiSwitch-track": {
          backgroundColor: "#1890ff",
          opacity: 1,
        },
      },
    },
    "& .MuiSwitch-thumb": {
      width: 16,
      height: 16,
      borderRadius: 8,
      transition: theme.transitions.create(["width"], {
        duration: 200,
      }),
    },
    "& .MuiSwitch-track": {
      borderRadius: 10,
      backgroundColor: "rgba(0,0,0,.25)",
      opacity: 1,
    },
  }));

export default FavForm;