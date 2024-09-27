import logo from './logo.svg';
import './App.css';
import Layout from './components/layouts/Layout';
import { Route, Routes } from 'react-router-dom';
import Post from './components/posts/Post';
import PostForm from './components/posts/PostForm';
import PostDetail from './components/posts/PostDetail';
import FavList from './components/favorite/FavList';
import FavForm from './components/favorite/FavForm';
import SignUp from './components/auth/SignUp';
import User from './components/users/User';
import Login from './components/auth/Login';
import Home from './components/common/Home';
import { LoginContext } from './contexts/LoginContext';
import { useProvideAuth } from './hooks/useProvideAuth';
import NotFound from './components/common/NotFound';
import Error from './components/common/Error';
import AccessControl from './components/common/AccessControl';
import { oauthAPI } from './api/services/oauth';
import { useEffect } from 'react';
import { setCookie } from './utils/cookieUtil';
import OAuthLogin from './components/auth/OAuthLogin';

function App() {
  const auth = useProvideAuth();

  return (
    <LoginContext.Provider value={auth}>
      <Layout>
        <Routes>
          <Route path='/' element={<Home />} />
          <Route path='/favorite' element={<AccessControl roleList={["ROLE_USER", "ROLE_ADMIN"]}><FavList /></AccessControl>} />  
          <Route path='/favorite/write' element={<AccessControl roleList={["ROLE_ADMIN"]}><FavForm /></AccessControl>} />
          <Route path='/favorite/modify/:favId' element={<AccessControl roleList={["ROLE_ADMIN"]}><FavForm /></AccessControl>} />
          
          <Route path='/post' element={<Post />} />
          <Route path='/post/write' element={<AccessControl roleList={["ROLE_USER", "ROLE_ADMIN"]}><PostForm /></AccessControl>} />
          <Route path='/post/modify/:postId' element={<AccessControl roleList={["ROLE_USER", "ROLE_ADMIN"]}><PostForm /></AccessControl>} />
          <Route path='/post/:postId' element={<AccessControl roleList={["ROLE_USER", "ROLE_ADMIN"]}><PostDetail /></AccessControl>} />
          
          <Route path='/login' element={<AccessControl roleList={["none"]}><Login /></AccessControl> } />
          <Route path='/signup' element={<AccessControl roleList={["none"]}><SignUp /></AccessControl> } />
          
          <Route path='/user' element={<AccessControl roleList={["ROLE_ADMIN"]}><User /></AccessControl>} />
          
          <Route path='/search' element={<Post />} />
          <Route path='/error' element={<Error />} />

          <Route path='/oauth/:provider' element={<OAuthLogin />} />
          <Route path='*' element={<NotFound />} />
        </Routes>
      </Layout>
    </LoginContext.Provider>
  );
}

export default App;
