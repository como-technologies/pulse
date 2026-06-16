// Gruvbox theming for mdbook-mermaid diagrams. Safe no-op when mermaid isn't present.
// Loads after mermaid.min.js/mermaid-init.js; the last initialize() before render wins.
(function () {
  if (typeof window === "undefined" || !window.mermaid) return;
  window.mermaid.initialize({
    startOnLoad: true,
    theme: "base",
    themeVariables: {
      darkMode: true,
      background: "#282828",
      fontFamily: '"Open Sans", "Segoe UI", sans-serif',
      // nodes
      mainBkg: "#3c3836",
      primaryColor: "#3c3836",
      primaryTextColor: "#ebdbb2",
      primaryBorderColor: "#a89984",
      nodeBorder: "#a89984",
      textColor: "#ebdbb2",
      secondaryColor: "#504945",
      tertiaryColor: "#32302f",
      // edges + labels
      lineColor: "#d5c4a1",
      edgeLabelBackground: "#1d2021",
      // subgraphs / clusters
      clusterBkg: "#32302f",
      clusterBorder: "#665c54",
      titleColor: "#fabd2f",
      // state / sequence / notes
      labelBackgroundColor: "#1d2021",
      noteBkgColor: "#504945",
      noteTextColor: "#ebdbb2",
      actorBkg: "#3c3836",
      actorBorder: "#a89984",
      actorTextColor: "#ebdbb2",
      signalColor: "#d5c4a1",
      signalTextColor: "#ebdbb2",
      errorBkgColor: "#cc241d",
      errorTextColor: "#ebdbb2",
    },
  });
})();
