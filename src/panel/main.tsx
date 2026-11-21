import React from 'react';
import { createRoot } from 'react-dom/client';
import { Panel } from './Panel';
import './index.css';

const container = document.getElementById('root');
if (!container) throw new Error('NetXRay: #root is missing from panel.html');

createRoot(container).render(
  <React.StrictMode>
    <Panel />
  </React.StrictMode>,
);
