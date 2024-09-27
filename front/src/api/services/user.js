import api from '../api';

export const userAPI = {
    login: (data) => api.post("/auth/login", data),
    getUserList : () => api.get("/auth"),
    addUser : (data) => api.post("/auth/signup", data),
    emailCheck: (email) => api.get("/auth/duplicate", { params : {email} }),
    modifyUser : (data) => api.patch("/auth", data),
    deleteUser : (data) => api.delete(`/auth`, {data: data}),
}