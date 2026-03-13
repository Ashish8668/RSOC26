import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Navbar from './components/Navbar';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import Report from './pages/Report';
import History from './pages/History';

export default function App() {
  return (
    <BrowserRouter>
      <Toaster position="top-right" toastOptions={{
        style: { background:'#1e2535', color:'#e8edf5', border:'1px solid #2a3347', fontFamily:"'Space Grotesk',sans-serif" }
      }}/>
      <Navbar />
      <Routes>
        <Route path="/"               element={<Home />} />
        <Route path="/scan/:scanId"   element={<Dashboard />} />
        <Route path="/report/:scanId" element={<Report />} />
        <Route path="/history"        element={<History />} />
      </Routes>
    </BrowserRouter>
  );
}
