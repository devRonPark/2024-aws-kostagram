import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Avatar,
  Box,
  Button,
  styled,
  Typography,
} from "@mui/material";
import ArrowForwardIosSharpIcon from "@mui/icons-material/ArrowForwardIosSharp";
import { useState } from "react";
import Swal from "sweetalert2";
import { favAPI } from "../../api/services/favorite";
import { useNavigate } from "react-router-dom";

const FavAccordion = ({fav, dispatch}) => {
  const navigate = useNavigate();
  const [isExpand, setIsExpand] = useState(false);
  const handleExpand = () => setIsExpand(prev=> !prev);
  const handleMove = () => {
    let urlLink = fav.url;
    if (!fav.url.startsWith("http://") && !fav.url.startsWith("https://")) {
      urlLink = `http://${fav.url}`;
    }
    window.open(urlLink, "_blank", "noopener, noreferrer");
  }
  const handleDelete = () => {
    Swal.fire({
      title: "확실해요?",
      text: "한 번 삭제하면 다시 되돌릴 수 없어요",
      showCancelButton: true,
      confirmButtonColor: "#3085d6",
      cancelButtonColor: "#d33",
      confirmButtonText: "응! 지워줘."
    }).then(async (result) => {
      if (result.isConfirmed) {
        try {
          const res = await favAPI.deleteFav(fav.id);
          if (res.status == 200) {
            Swal.fire({
              text: "삭제되었습니다.",
              icon: "success"
            });
            dispatch({type:"DELETE_FAV", payload: fav})
          }
        } catch (error) {
          console.error(error);
          navigate("/error", {state: error.message});
        }
      }
    });
  }

  const handleModify = () => {
    navigate(`/favorite/modify/${fav.id}`, { state : fav });
  }

  console.log(fav);
  return (
    <MyAccordion expanded={isExpand} onClick={handleExpand}>
      <MyAccordionSummary>
        <Box sx={{display: "flex", justifyContent: "space-between", width: "100%"}}>
          <Avatar alt={fav.title} src={`${process.env.REACT_APP_SERVER}/img/${fav.image?.saved}`} />
          <span>{fav.id}</span>
          <span style={{width: "40%"}}>{fav.title}</span>
          <Button onClick={handleModify}>수정</Button>
          <Button onClick={handleDelete}>삭제</Button>
        </Box>
      </MyAccordionSummary>
      <MyAccordionDetails>
        <Button onClick={handleMove}>{fav.url}</Button>
      </MyAccordionDetails>
    </MyAccordion>
  );
};

const MyAccordion = styled((props) => (
  <Accordion disableGutters elevation={0} square {...props} />
))(({ theme }) => ({
  border: `1px solid ${theme.palette.divider}`,
  "&:not(:last-child)": {
    borderBottom: 0,
  },
  "&::before": {
    display: "none",
  },
}));

const MyAccordionSummary = styled((props) => (
  <AccordionSummary
    expandIcon={<ArrowForwardIosSharpIcon sx={{ fontSize: "0.9rem" }} />}
    {...props}
  />
))(({ theme }) => ({
  backgroundColor: "rgba(0, 0, 0, .03)",
  flexDirection: "row-reverse",
  "& .MuiAccordionSummary-expandIconWrapper.Mui-expanded": {
    transform: "rotate(90deg)",
  },
  "& .MuiAccordionSummary-content": {
    marginLeft: theme.spacing(1),
  },
  ...theme.applyStyles("dark", {
    backgroundColor: "rgba(255, 255, 255, .05)",
  }),
}));

const MyAccordionDetails = styled(AccordionDetails)(({ theme }) => ({
  padding: theme.spacing(2),
  borderTop: "1px solid rgba(0, 0, 0, .125)",
}));

export default FavAccordion;
