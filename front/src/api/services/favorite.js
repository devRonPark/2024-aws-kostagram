import api from '../api';

export const favAPI = {
    getFavList : () => api.get("/favorite"),
    writeFav : (formData) => api.post("/favorite", formData, { headers: {"Content-Type": "multipart/form-data"} }),
    modifyFav : (formData) => api.patch("/favorite", formData, { headers: {"Content-Type": "multipart/form-data"} }),
    deleteFav : (id) => api.delete(`/favorite/${id}`)
}