import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import {createTheme, ThemeProvider} from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import { CookiesProvider } from 'react-cookie';

const root = ReactDOM.createRoot(document.getElementById('root'));

let theme = createTheme({ });
theme = createTheme(theme, {
  palette: {
    main: theme.palette.augmentColor({color: { main: '#F17F42', contrastText: '#FFF' }}),
    sub: theme.palette.augmentColor({color: { main: '#CE6D39', contrastText: '#FFF'}}),
    bg1: theme.palette.augmentColor({color: { main: '#FFEEE4', contrastText: '#383A3F'}}),
    bg2: theme.palette.augmentColor({color: { main: '#FBFFB9', contrastText: '#383A3F'}}),
    font: theme.palette.augmentColor({color: { main: '#383A3F'}}),
  },
});

root.render(
  // <React.StrictMode>
  <ThemeProvider theme={theme}>
    <CssBaseline />
    <CookiesProvider>
      <App />
    </CookiesProvider>
  </ThemeProvider>
  // </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
