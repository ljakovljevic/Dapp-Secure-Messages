import { useState } from "react";
import Send from "./pages/Send";
import RegisterKey from "./pages/RegisterKey";
import Inbox from "./pages/Inbox";
import Connect from "./components/Connect";
import './styles.css';

type Tab = "send" | "register" | "inbox";

export default function App() {
  const [tab, setTab] = useState<Tab>("send");

  return (
    <div className="shell">
      <div className="card">
        <h2 style={{ color: "rgb(103,58,183)", textAlign: "center", marginTop: 0 }}>
          Encrypted Messaging
        </h2>

        <div>
          <Connect />
        </div>

        <div className="tabs">
          <button className="tab-btn" data-active={tab==="send"} onClick={()=>setTab("send")}>Send</button>
          <button className="tab-btn" data-active={tab==="register"} onClick={()=>setTab("register")}>Register Key</button>
          <button className="tab-btn" data-active={tab==="inbox"} onClick={()=>setTab("inbox")}>Inbox</button>
        </div>

        {tab==="send" && <Send/>}
        {tab==="register" && <RegisterKey/>}
        {tab==="inbox" && <Inbox/>}
      </div>
    </div>
  );
}