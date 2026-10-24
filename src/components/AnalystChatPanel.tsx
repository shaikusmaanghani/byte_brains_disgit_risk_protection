import React, { useState } from 'react';
import { Bot, MessageCircle, Send, X } from 'lucide-react';
import { apiClient } from '../services/apiClient';

interface ChatMessage {
  role: 'analyst' | 'assistant';
  text: string;
}

export const AnalystChatPanel: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: 'assistant', text: 'Ask about the detection database. I only answer from recorded findings and history.' },
  ]);

  const ask = async (event: React.FormEvent) => {
    event.preventDefault();
    const prompt = question.trim();
    if (!prompt || busy) return;
    setQuestion('');
    setMessages((items) => [...items, { role: 'analyst', text: prompt }]);
    setBusy(true);
    try {
      const answer = await apiClient.askAnalystAssistant(prompt);
      setMessages((items) => [...items, { role: 'assistant', text: answer }]);
    } catch (error) {
      setMessages((items) => [...items, { role: 'assistant', text: error instanceof Error ? error.message : 'Assistant request failed.' }]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed bottom-5 right-5 z-40">
      {open ? (
        <section aria-label="Analyst assistant" className="w-[min(390px,calc(100vw-2rem))] h-[min(540px,calc(100vh-7rem))] flex flex-col rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl">
          <header className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <div className="flex items-center gap-2 text-sm font-bold text-white"><Bot className="w-4 h-4 text-cyan-300" /> Analyst assistant <span className="text-[9px] text-emerald-300 border border-emerald-800 rounded px-1">OFFLINE</span></div>
            <button aria-label="Close assistant" onClick={() => setOpen(false)} className="text-slate-400 hover:text-white"><X className="w-4 h-4" /></button>
          </header>
          <div className="flex-1 overflow-y-auto p-3 space-y-3" aria-live="polite">
            {messages.map((message, index) => (
              <div key={`${index}-${message.role}`} className={`max-w-[92%] whitespace-pre-wrap rounded-xl px-3 py-2 text-xs leading-relaxed ${message.role === 'analyst' ? 'ml-auto bg-cyan-950 text-cyan-100' : 'bg-slate-800 text-slate-200'}`}>
                {message.text}
              </div>
            ))}
            {busy && <p className="text-[11px] text-slate-500">Looking up recorded evidence…</p>}
          </div>
          <div className="px-3 pb-2 flex gap-1.5 flex-wrap">
            {['Top 5 risks', 'Summarize the queue'].map((prompt) => (
              <button key={prompt} onClick={() => setQuestion(prompt)} className="text-[10px] px-2 py-1 rounded-full border border-slate-700 text-slate-400 hover:text-cyan-200">{prompt}</button>
            ))}
          </div>
          <form onSubmit={ask} className="flex gap-2 p-3 border-t border-slate-800">
            <input value={question} onChange={(event) => setQuestion(event.target.value)} aria-label="Ask about detections" placeholder="Ask about detection IDs…" className="min-w-0 flex-1 rounded-lg bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500" />
            <button disabled={busy || !question.trim()} aria-label="Send question" className="rounded-lg bg-cyan-600 px-3 text-white disabled:opacity-50"><Send className="w-4 h-4" /></button>
          </form>
        </section>
      ) : (
        <button onClick={() => setOpen(true)} className="flex items-center gap-2 rounded-full px-4 py-3 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-xl">
          <MessageCircle className="w-4 h-4" /> Ask analyst assistant
        </button>
      )}
    </div>
  );
};
