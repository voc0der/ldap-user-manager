<?php
declare(strict_types=1);

/**
 * Masked-token → username mapper for LUM.
 * Reads /opt/ldap_user_manager/data/xxxx/jf_token_map.json
 * and replaces labels like "175a12d5…0941" with "brocoder" when known.
 */

const JF_MAP_PATH = '/opt/ldap_user_manager/data/jellyfin-users/jf_token_map.json';
const JF_MAP_TTL  = 43200; // 12h

/**
 * Load the JSON map (cached). Returns ['map'=>[masked => username], 'etag'=>..., 'generated_at'=>...]
 */
function jf_map_get(): array {
    static $mem = null, $mem_time = 0;

    // APCu cache if available
    if (function_exists('apcu_fetch')) {
        $hit = apcu_fetch('jf_map_blob', $ok);
        if ($ok && is_array($hit)) return $hit;
    }

    // In-process soft cache
    if ($mem && (time() - $mem_time) < 5) return $mem;

    $out = ['map' => []];
    if (is_file(JF_MAP_PATH) && is_readable(JF_MAP_PATH)) {
        $raw = @file_get_contents(JF_MAP_PATH);
        if ($raw !== false) {
            $j = json_decode($raw, true);
            if (is_array($j) && !empty($j['map']) && is_array($j['map'])) {
                $out = ['map' => $j['map'], 'etag' => ($j['etag'] ?? null), 'generated_at' => ($j['generated_at'] ?? null)];
            }
        }
    }

    if (function_exists('apcu_store')) @apcu_store('jf_map_blob', $out, JF_MAP_TTL);
    $mem = $out; $mem_time = time();
    return $out;
}

/** Does the string look like one of our masked tokens (contains the single-character ellipsis)? */
function jf_is_masked_token_label(string $s): bool {
    // Fast check for the Unicode ellipsis char used in your masks.
    return (mb_strpos($s, '…') !== false);
}

/** Prefer a username from the map when label is a masked token. */
function jf_prefer_username_for_label(string $label): string {
    if ($label === '' || !jf_is_masked_token_label($label)) return $label;
    $map = jf_map_get()['map'] ?? [];
    if (isset($map[$label]) && is_string($map[$label]) && $map[$label] !== '') {
        return $map[$label];
    }
    return $label;
}

/** Recursively rewrite labels in a decoded API JSON payload. */
function jf_map_rewrite_response(mixed $data): mixed {
    if (is_array($data)) {
        // If it's a list payload: { ok, entries: [...] }
        if (isset($data['entries']) && is_array($data['entries'])) {
            foreach ($data['entries'] as $i => $row) {
                if (is_array($row)) {
                    if (isset($row['label']) && is_string($row['label'])) {
                        $data['entries'][$i]['label'] = jf_prefer_username_for_label($row['label']);
                    }
                    // Some versions also show 'host' or 'user' fields — prefer rewrite when they look masked
                    if (isset($row['user']) && is_string($row['user']) && jf_is_masked_token_label($row['user'])) {
                        $data['entries'][$i]['user'] = jf_prefer_username_for_label($row['user']);
                    }
                    if (isset($row['host']) && is_string($row['host']) && jf_is_masked_token_label($row['host'])) {
                        $data['entries'][$i]['host'] = jf_prefer_username_for_label($row['host']);
                    }
                }
            }
        } else {
            // Single-result payloads (add/update/delete/prune/clear)
            foreach (['label','user','host'] as $k) {
                if (isset($data[$k]) && is_string($data[$k]) && jf_is_masked_token_label($data[$k])) {
                    $data[$k] = jf_prefer_username_for_label($data[$k]);
                }
            }
        }
    }
    return $data;
}
