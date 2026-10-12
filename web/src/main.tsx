import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, App as AntApp } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import enUS from 'antd/locale/en_US';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import App from './App';
import { currentLang } from './i18n';

// antd 内置文案（分页/日期/空态等）跟随应用语言（#69：此前固定 zh_CN，英文界面下混显中文）
const isZh = currentLang() === 'zh';
const antdLocale = isZh ? zhCN : enUS;
dayjs.locale(isZh ? 'zh-cn' : 'en');

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider locale={antdLocale} theme={{ token: { colorPrimary: '#2f54eb' } }}>
      <AntApp>
        <App />
      </AntApp>
    </ConfigProvider>
  </React.StrictMode>,
);
