import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./theme.css";
import { AuthProvider } from "./auth";
import App from "./App.tsx";
import { RootErrorBoundary } from "./shell/RootErrorBoundary";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: false } },
});

// `useBlocker` needs a data router. RootErrorBoundary is inside the route
// element, above the default error element of the root route.
const router = createBrowserRouter([
  {
    path: "*",
    element: (
      <RootErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>
            <App />
          </AuthProvider>
        </QueryClientProvider>
      </RootErrorBoundary>
    ),
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
