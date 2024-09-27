import api from '../api';

export const postAPI = {
    getPostList : () => api.get("/post"),
    getPost : (id) => api.get(`/post/${id}`),
    writePost : (formData) => api.post("/post", formData, { headers: {"Content-Type": "multipart/form-data"} }),
    modifyPost : (formData) => api.patch("/post", formData, { headers: {"Content-Type": "multipart/form-data"} }),
    deletePost : (id, password, authorId) => api.delete(`/post/${id}`, { data: { password, authorId } }),
    searchPost : (keyword) => api.get("/post/search", { params : {keyword} }),
}