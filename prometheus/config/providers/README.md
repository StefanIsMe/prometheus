# `prometheus/config/providers/` — per-provider helper modules

Each file in this package owns one provider:

| File | Provider | Notes |
| --- | --- | --- |
| `tokenrouter.py` | TokenRouter | Custom OpenAI-compatible proxy. Reads `TOKENROUTER_API_KEY` from env. |
| `openrouter.py` | OpenRouter | Auto-injects `HTTP-Referer` / `X-Title` attribution headers. Flags every model with `drop_tool_choice_with_thinking` (DeepSeek may be the upstream); `openrouter/auto` also gets `force_store_false`. |
| `deepseek.py` | DeepSeek | Reads `DEEPSEEK_API_KEY` from env. `tool_choice` suppression is handled by `_THINKING_NO_TOOL_CHOICE_PROVIDERS` in `llm_config.py`. |
| `anthropic.py` | Anthropic | Reads `ANTHROPIC_API_KEY`. Protocol is `anthropic` (Messages API). |
| `custom.py` | Custom | Wildcard for any vendor not in the registry. Pick `protocol: openai` or `protocol: anthropic` explicitly. |
| `base.py` | (shared) | `ProviderHelper` protocol, `ProviderParseResult`, and shared parsers. |
| `__init__.py` | (registry) | `PROVIDER_HELPERS` dict + `get_helper()` / `is_known_provider()`. |

## Adding a new provider

1. Create `myprovider.py` next to the others.
2. Implement `build_helper()` returning a `ProviderHelper` (see
   `tokenrouter.py` for the smallest possible example).
3. Register it in `__init__.py`.

The loader (`prometheus/config/llm_config.py:_parse_config`) picks it
up automatically. No other wiring required.

## Opting out of a helper

Set `type: custom` in the YAML to force the inline parser for a
provider whose name has a registered helper:

```yaml
providers:
  openrouter:
    type: custom
    base_url: https://my-fork.example/v1
```
