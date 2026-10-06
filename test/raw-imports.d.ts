// import.meta.glob(), without the browser globals that vite/client declares.
/// <reference types="vite/types/importMeta.d.ts" />

// Vite's ?raw suffix imports a file's contents as a string.
declare module '*?raw' {
  const content: string;
  export default content;
}
