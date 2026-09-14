# M.Tech CSE AI Portfolio Blueprint & Engineering Specification

A production-grade, systems-first architecture blueprint tailored for an **M.Tech in Computer Science and Engineering** portfolio. Features an interactive RAG terminal/chat drawer, in-browser edge AI model inference (via Transformers.js / ONNX Runtime Web), and an accessible 3-way theme switching engine (Light, Dark, System).

---

## 1. Key Technical Value Propositions

1. **Interactive RAG Terminal / Chat Drawer:**
   - An intelligent AI agent grounded on your CV, thesis dissertation, research papers, published benchmarks, and GitHub repositories.
   - Sub-second streaming responses via Vercel AI SDK and serverless vector indexing.

2. **In-Browser Client-Side AI Showcase:**
   - Zero-server client inference executing directly in the visitor's browser via WebAssembly (Wasm) and WebGPU (`@xenova/transformers`).
   - Demonstrates applied machine learning, quantisation, and edge deployment competencies.

3. **Systems & Research-Oriented UX:**
   - High-contrast developer theme with JetBrains Mono / Inter typography.
   - Interactive Mermaid.js system architecture flowcharts, latency/throughput telemetry badges, and collapsible benchmark dossiers.

---

## 2. Recommended Tech Stack

| Layer | Technology | Justification for M.Tech CSE Profile |
| :--- | :--- | :--- |
| **Framework** | Next.js 14+ (App Router, TypeScript) | Industry benchmark for SSR/SSG, Edge API route handlers, and SEO performance. |
| **Styling** | Tailwind CSS + Lucide Icons | Utility-first styling with zero runtime overhead and flexible dark/light theme switching. |
| **AI Runtime** | Vercel AI SDK (`ai`, `@ai-sdk/openai`) | Streaming token delivery, structured tool use, and multi-model abstraction. |
| **Vector DB** | Upstash Vector or Pinecone Serverless | Low-latency cosine similarity vector lookups with zero operational overhead. |
| **LLM Inference** | OpenAI `gpt-4o-mini` / Groq `llama-3.3-70b` | High-accuracy technical synthesis with sub-500ms initial token generation. |
| **Edge AI** | `@xenova/transformers` (Transformers.js) | Client-side quantized ONNX neural inference running locally on WebGPU/WASM. |
| **CI/CD** | GitHub Actions + Vercel / Cloudflare Pages | Automated linting, type-safety validation, and continuous preview deployments. |


---

## 3. Step-by-Step Implementation Roadmap

### Phase 1: Project Scaffolding
```bash
npx create-next-app@latest mtech-portfolio \
  --typescript \
  --tailwind \
  --eslint \
  --app \
  --src-dir \
  --import-alias "@/*"

cd mtech-portfolio
npm install ai @ai-sdk/openai @upstash/vector lucide-react clsx tailwind-merge framer-motion @xenova/transformers
```

---

### Phase 2: Structured Knowledge Ingestion (RAG Pipeline)

1. **Profile Data Schema (`data/knowledge.json`):**
```json
[
  {
    "id": "thesis-01",
    "category": "research",
    "title": "M.Tech Thesis: Efficient Distributed Graph Neural Networks",
    "content": "Specializing in distributed systems and deep learning. Research focuses on dynamic graph partitioning to reduce communication overhead in Multi-GPU clusters. Advised by Dr. X. Tools: PyTorch Geometric, CUDA, DGL, Ray."
  },
  {
    "id": "proj-distributed-kv",
    "category": "systems",
    "title": "Raft-Consensus Distributed KV Store",
    "content": "Engineered a fault-tolerant, linearly scalable Key-Value database in Go. Implemented Raft leader election, log replication, and snapshotting. Benchmarked 45k ops/sec with sub-5ms p99 latency."
  },
  {
    "id": "edu-mtech",
    "category": "education",
    "title": "M.Tech in Computer Science and Engineering",
    "content": "Core coursework: Distributed Systems, Advanced Algorithms, Deep Learning, High Performance Computing (HPC), Database Internals. Current CPI/CGPA: 9.2/10."
  }
]
```

2. **Vector Indexing Script (`scripts/index-knowledge.ts`):**
```typescript
import { Index } from "@upstash/vector";
import knowledgeData from "../data/knowledge.json";

const index = new Index({
  url: process.env.UPSTASH_VECTOR_REST_URL!,
  token: process.env.UPSTASH_VECTOR_REST_TOKEN!,
});

async function populateVectorDB() {
  console.log("Upserting knowledge vectors...");
  for (const doc of knowledgeData) {
    await index.upsert({
      id: doc.id,
      data: `${doc.title}\n${doc.content}`,
      metadata: { category: doc.category, title: doc.title },
    });
  }
  console.log("Ingestion completed successfully.");
}

populateVectorDB();
```


---

### Phase 3: Streaming AI Endpoint (`src/app/api/chat/route.ts`)

```typescript
import { openai } from "@ai-sdk/openai";
import { streamText } from "ai";
import { Index } from "@upstash/vector";

const index = new Index({
  url: process.env.UPSTASH_VECTOR_REST_URL!,
  token: process.env.UPSTASH_VECTOR_REST_TOKEN!,
});

export const runtime = "edge";

export async function POST(req: Request) {
  const { messages } = await req.json();
  const latestUserMessage = messages[messages.length - 1]?.content || "";

  // 1. Vector Cosine Search for Grounding Context
  let contextText = "";
  try {
    const searchResults = await index.query({
      data: latestUserMessage,
      topK: 3,
      includeMetadata: true,
    });
    contextText = searchResults
      .map((res) => `[Source: ${res.metadata?.title}]: ${res.data}`)
      .join("\n\n");
  } catch (err) {
    console.warn("Vector query fallback triggered:", err);
  }

  // 2. Stream Grounded Response with Strict Guardrails
  const systemPrompt = `You are the AI Research & Systems Engineering Assistant for an M.Tech CSE scholar.
Answer technical inquiries regarding their dissertation, distributed algorithms, high-performance computing, benchmarks, and published code.
Always adhere strictly to the verified context. If unsure, direct the reviewer to inspect the relevant GitHub repository or published PDF.

[VERIFIED SCHOLAR CONTEXT]:
${contextText}
`;

  const result = await streamText({
    model: openai("gpt-4o-mini"),
    system: systemPrompt,
    messages,
  });

  return result.toDataStreamResponse();
}
```

---

## 4. 3-Way Robust Theme Switcher Engine (Light, Dark, System)

### A. Zero-FOUC Blocking Head Script (`src/app/layout.tsx` or `<head>`):
```html
<script>
  (function() {
    try {
      var storedTheme = localStorage.getItem('theme') || 'system';
      var systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (storedTheme === 'dark' || (storedTheme === 'system' && systemDark)) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    } catch (e) {}
  })();
</script>
```

### B. React Theme Provider & Dynamic OS Listener Hook (`src/hooks/useTheme.ts`):
```typescript
"use client";
import { useState, useEffect } from "react";

export type ThemeMode = "light" | "dark" | "system";

export function useTheme() {
  const [theme, setTheme] = useState<ThemeMode>("system");

  useEffect(() => {
    const saved = (localStorage.getItem("theme") as ThemeMode) || "system";
    setTheme(saved);
    applyTheme(saved);

    // Dynamic OS preference listener
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = () => {
      if (localStorage.getItem("theme") === "system" || !localStorage.getItem("theme")) {
        applyTheme("system");
      }
    };
    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
  }, []);

  const applyTheme = (mode: ThemeMode) => {
    const isDark =
      mode === "dark" ||
      (mode === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    if (isDark) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  };

  const updateTheme = (newMode: ThemeMode) => {
    setTheme(newMode);
    localStorage.setItem("theme", newMode);
    applyTheme(newMode);
  };

  return { theme, updateTheme };
}
```

---

## 5. M.Tech CSE Professional Layout Blueprint

1. **Hero & Research Specialization Matrix:**
   - Formal Scholar Title, Institution, and Research Lab.
   - Core research areas: Distributed Systems, High-Performance Computing, Graph Neural Networks, LLM Optimization.
   - Telemetry Badges: Accepted Papers (IEEE/ACM/ArXiv), Cumulative Citations, GitHub Commits.

2. **Dissertation & Research Dossiers:**
   - Problem statement, mathematical formulation, distributed cluster architecture, communication overhead reduction metrics, baseline comparisons, and throughput graphs.

3. **Systems Engineering Case Studies:**
   - Architecture Diagrams (Mermaid.js), RPC serialization benchmarks, cache-invalidation strategies, fault tolerance mechanisms, and direct links to reproduction scripts.

4. **Interactive Client-Side AI Benchmark Showcase:**
   - Live quantized token classifier executing in WebAssembly / WebGPU on the user's browser without calling backend servers.

