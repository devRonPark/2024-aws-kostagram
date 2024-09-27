import { useNavigate } from "react-router-dom";
import { Box, Button } from "@mui/material";
import { useEffect, useReducer, useState } from "react";
import { favAPI } from "../../api/services/favorite";
import FavAccordion from "./FavAccordion";

const favListReducer = (state, action) => {
  switch (action.type) {
      case "SET_FAVS":
          return action.payload;
      case "DELETE_FAV":
          return state.filter(fav => fav.id != action.payload.id);
  }
}

const FavList = () => {
  const [favList, dispatch] = useReducer(favListReducer, []);
  const navigate = useNavigate();
  const getFavList = async () => {
    try {
      const res = await favAPI.getFavList();
      dispatch({type: "SET_FAVS", payload: res.data});
    } catch (error) {
      console.error(error);
      // navigate("/error", {state: error.message});
    }
  };

  useEffect(() => {
    getFavList();
  }, []);


  return (
    <>
      <Button onClick={() => navigate("/favorite/write")}>즐겨찾기 추가</Button>
      
      <Box sx={{width: "500px"}}>
        {favList.map((fav) => (
          <FavAccordion key={fav.id} fav={fav} dispatch={dispatch}/>
        ))}
      </Box>
    </>
  );
};

export default FavList;
