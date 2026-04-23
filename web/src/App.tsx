import { Route, Routes } from "react-router-dom";

import Layout from "@/components/Layout";
import Dashboard from "@/pages/Dashboard";
import Block from "@/pages/Block";
import Transaction from "@/pages/Transaction";
import Address from "@/pages/Address";
import Bridge from "@/pages/Bridge";
import Network from "@/pages/Network";
import Search from "@/pages/Search";
import NotFound from "@/pages/NotFound";

import AdminLayout from "@/pages/admin/AdminLayout";
import AdminDashboard from "@/pages/admin/Dashboard";
import AdminGovernance from "@/pages/admin/Governance";
import AdminConfig from "@/pages/admin/Config";
import AdminProver from "@/pages/admin/Prover";
import AdminLogs from "@/pages/admin/Logs";
import AdminSession from "@/pages/admin/Session";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/block/:id" element={<Block />} />
        <Route path="/tx/:hash" element={<Transaction />} />
        <Route path="/address/:address" element={<Address />} />
        <Route path="/bridge" element={<Bridge />} />
        <Route path="/network" element={<Network />} />
        <Route path="/search" element={<Search />} />

        <Route path="/admin/session" element={<AdminSession />} />
        <Route path="/admin" element={<AdminLayout />}>
          <Route index element={<AdminDashboard />} />
          <Route path="governance" element={<AdminGovernance />} />
          <Route path="config" element={<AdminConfig />} />
          <Route path="prover" element={<AdminProver />} />
          <Route path="logs" element={<AdminLogs />} />
        </Route>

        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
