# deck

`build_deck.js` (Japanese) and `build_deck_en.js` (English) generate the 37-slide decks with pptxgenjs (`npm i pptxgenjs`).
They load a theme helper from `/mnt/skills/public/pptx/scripts/apply_theme.js`, which exists only in the original authoring environment; to run elsewhere, remove the `applyTheme` import/calls or supply your own. The generated decks are included: `AI_agent_attack_tools_analysis.pptx` (JP) and `AI_agent_attack_tools_analysis_EN.pptx` (EN).
