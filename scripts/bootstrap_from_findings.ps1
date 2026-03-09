param(
  [string]$Root = "MoveSafe_skills",
  [string]$FindingsPath = "Moveval/audit.json/audit_platform/findings.jsonl",
  [string]$AiFindingsPath = "Moveval/audit.json/audit_platform/ai_audit_findings.jsonl"
)

$ErrorActionPreference = "Stop"

function Write-Utf8NoBom {
  param([string]$Path,[string]$Content)
  $d=Split-Path -Parent $Path
  if($d -and !(Test-Path $d)){ New-Item -ItemType Directory -Force -Path $d | Out-Null }
  [System.IO.File]::WriteAllText($Path,$Content,[System.Text.UTF8Encoding]::new($false))
}

function Normalize-Title([string]$s){ if(!$s){return ''}; return ([regex]::Replace($s.ToLowerInvariant().Trim(),'\s+',' ')) }

function Parse-FindingsLine([string]$path,[string]$source,[string]$pathField,[string]$suggField){
  $recs=New-Object System.Collections.Generic.List[object]; $bad=0
  Get-Content $path | ForEach-Object {
    if([string]::IsNullOrWhiteSpace($_)){ return }
    try{
      $o = $_ | ConvertFrom-Json -ErrorAction Stop
      $p=''; if($o.PSObject.Properties.Name -contains $pathField){ $p=[string]$o.$pathField }
      $s=''; if($o.PSObject.Properties.Name -contains $suggField){ $s=[string]$o.$suggField }
      $recs.Add([pscustomobject]@{source=$source;title=[string]$o.title;description=[string]$o.description;suggestion=$s;severity=[string]$o.severity;path=$p})
    }catch{ $bad++ }
  }
  [pscustomobject]@{records=$recs;bad=$bad;valid=$recs.Count}
}

function Parse-AiMulti([string]$path,[string]$source){
  $recs=New-Object System.Collections.Generic.List[object]; $bad=0; $buf=''
  foreach($line in Get-Content $path){
    if([string]::IsNullOrWhiteSpace($buf)){ if([string]::IsNullOrWhiteSpace($line)){ continue }; $buf=$line } else { $buf += "`n" + $line }
    try{
      $o = $buf | ConvertFrom-Json -ErrorAction Stop
      $p=''; if($o.PSObject.Properties.Name -contains 'file_path'){ $p=[string]$o.file_path }
      $s=''; if($o.PSObject.Properties.Name -contains 'fix_suggestion'){ $s=[string]$o.fix_suggestion }
      $recs.Add([pscustomobject]@{source=$source;title=[string]$o.title;description=[string]$o.description;suggestion=$s;severity=[string]$o.severity;path=$p})
      $buf=''
    }catch{
      if($buf.Length -gt 800000){ $bad++; $buf='' }
    }
  }
  if(-not [string]::IsNullOrWhiteSpace($buf)){ $bad++ }
  [pscustomobject]@{records=$recs;bad=$bad;valid=$recs.Count}
}

function Get-CrossPathGroups($items,[int]$limit=20){
  $out=@()
  $g = $items | Where-Object { $_.title -and $_.path } | Group-Object { Normalize-Title $_.title }
  foreach($it in $g){
    $paths=@($it.Group | ForEach-Object { $_.path } | Where-Object { $_ } | Sort-Object -Unique)
    if($paths.Count -lt 2){ continue }
    $name=($it.Group | Group-Object title | Sort-Object Count -Descending | Select-Object -First 1).Name
    $out += [pscustomobject]@{title=$name;total_count=$it.Count;unique_path_count=$paths.Count;sample_paths=@($paths | Select-Object -First 8)}
  }
  @($out | Sort-Object unique_path_count,total_count -Descending | Select-Object -First $limit)
}

$plugins=@(
  [pscustomobject]@{slug='governance-centralization-analysis'; title='Governance and Centralization Analysis'; pattern='centraliz|owner|admin|multisig|timelock'},
  [pscustomobject]@{slug='event-observability-analysis'; title='Event and Observability Analysis'; pattern='event emit|missing events|indexed'},
  [pscustomobject]@{slug='access-control-initialization-analysis'; title='Access Control and Initialization Analysis'; pattern='access control|authoriz|auth|initializ|front-run'},
  [pscustomobject]@{slug='input-validation-arithmetic-safety'; title='Input Validation and Arithmetic Safety'; pattern='missing parameter|validation|unchecked|bounds|precision|round|overflow|underflow|slippage|decimal'},
  [pscustomobject]@{slug='external-call-token-compatibility'; title='External Call and Token Compatibility'; pattern='transferfrom|safetransfer|deflation|fee-on-transfer|rebas|external call|erc20'},
  [pscustomobject]@{slug='signature-replay-analysis'; title='Signature and Replay Analysis'; pattern='signature|replay|eip-712|permit|nonce|malleability|ecrecover'},
  [pscustomobject]@{slug='upgradeability-storage-safety'; title='Upgradeability and Storage Safety'; pattern='upgrade|proxy|storage gap|storage collision|diamond|uups|beacon'},
  [pscustomobject]@{slug='dos-gas-griefing-analysis'; title='DoS, Gas, and Griefing Analysis'; pattern='dos|denial of service|gas|unbounded|loop|grief'},
  [pscustomobject]@{slug='reentrancy-state-transition-analysis'; title='Reentrancy and State Transition Analysis'; pattern='reentranc|callback|cei'},
  [pscustomobject]@{slug='code-hygiene-maintainability-analysis'; title='Code Hygiene and Maintainability Analysis'; pattern='unused|redundant|duplicate|optimization|typo|comment|dead code'},
  [pscustomobject]@{slug='oracle-flashloan-hot-potato-analysis'; title='Oracle, Flash Loan, and Hot Potato Analysis'; pattern='oracle|price feed|chainlink|pyth|twap|flash ?loan|flashloan|hot[- ]potato|price voucher|pricevouch|stale price|minanswer|maxanswer|latestrounddata|sandwich|price manipulation'},
  [pscustomobject]@{slug='move-object-ptbs-analysis'; title='Move Object and PTBs Analysis'; pattern='\.move\b|\bobject\b|\buid\b|\bability\b|\bstore\b|\bkey\b|hot[- ]potato|\bptb\b|\bptbs\b|programmable transaction block'}
)

if(!(Test-Path $FindingsPath)){ throw "Missing: $FindingsPath" }
if(!(Test-Path $AiFindingsPath)){ throw "Missing: $AiFindingsPath" }

$parsedFindings = Parse-FindingsLine -path $FindingsPath -source 'findings' -pathField 'location_filename' -suggField 'suggestion'
$parsedAi = Parse-AiMulti -path $AiFindingsPath -source 'ai_audit_findings'
$records=@(); $records += $parsedFindings.records; $records += $parsedAi.records
if($records.Count -eq 0){ throw 'No valid records parsed.' }

$globalCross = Get-CrossPathGroups -items $records -limit 100
$aiTypeTop = $parsedAi.records | Group-Object title | Sort-Object Count -Descending | Select-Object -First 80 | ForEach-Object { [pscustomobject]@{title=$_.Name; count=$_.Count} }

$moveRegex=[regex]::new('\.move\b|\bobject\b|\buid\b|\bability\b|\bstore\b|\bkey\b|hot[- ]potato',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$ptbRegex=[regex]::new('\bptb\b|\bptbs\b|programmable transaction block',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$moveGlobal=@($records | Where-Object { $moveRegex.IsMatch(([string]$_.title+' '+[string]$_.description+' '+[string]$_.suggestion+' '+[string]$_.path) ) })
$ptbGlobal=@($records | Where-Object { $ptbRegex.IsMatch(([string]$_.title+' '+[string]$_.description+' '+[string]$_.suggestion+' '+[string]$_.path) ) })

$pluginSignals=@()
foreach($pl in $plugins){
  $rg=[regex]::new($pl.pattern,[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  $m=@($records | Where-Object { $rg.IsMatch(([string]$_.title+' '+[string]$_.description+' '+[string]$_.suggestion+' '+[string]$_.path)) })
  $src=@($m | Group-Object source | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{source=$_.Name;count=$_.Count} })
  $top=@($m | Group-Object title | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object { [pscustomobject]@{title=$_.Name;count=$_.Count} })
  $cross=Get-CrossPathGroups -items $m -limit 25

  $pluginSignals += [pscustomobject]@{
    plugin=$pl.slug; title=$pl.title; matched_count=$m.Count; source_breakdown=$src; cross_path_group_count=$cross.Count; top_titles=$top
  }

  $pluginRoot=Join-Path $Root ('plugins/'+$pl.slug)
  $skill=Join-Path $pluginRoot ('skills/'+$pl.slug)
  $ref=Join-Path $skill 'references'
  $meta=Join-Path $pluginRoot '.claude-plugin'
  New-Item -ItemType Directory -Force -Path $pluginRoot,$skill,$ref,$meta | Out-Null

  $pjson=[ordered]@{name=$pl.slug;version='0.1.0-draft';description=$pl.title;author=[ordered]@{name='MoveSafe';url='https://movesafe.local'}} | ConvertTo-Json -Depth 5
  Write-Utf8NoBom (Join-Path $meta 'plugin.json') $pjson

  $skillMd=@(
    '---',
    ('name: '+$pl.slug),
    ('description: '+$pl.title+' skill generated from merged findings sources.'),
    '---','',('# '+$pl.title),'',
    '## Workflow','1. Scope','2. Match patterns','3. Compare same-vulnerability different paths','4. Assess exploitability','5. Report with evidence','',
    '## References',
    '- references/finding-signals.md',
    '- references/cross-path-patterns.md',
    '- references/triage-checklist.md'
  )
  if($pl.slug -eq 'oracle-flashloan-hot-potato-analysis'){ $skillMd += '- references/hot-potato-priority.md' }
  if($pl.slug -eq 'move-object-ptbs-analysis'){ $skillMd += '- references/move-object-priority.md'; $skillMd += '- references/ptbs-priority.md' }
  Write-Utf8NoBom (Join-Path $skill 'SKILL.md') ($skillMd -join "`n")

  $sigRows=@($top | ForEach-Object { '| '+([string]$_.title).Replace('|','\\|')+' | '+$_.count+' |' })
  if($sigRows.Count -eq 0){ $sigRows=@('| (no matches) | 0 |') }
  $srcRows=@($src | ForEach-Object { '| '+$_.source+' | '+$_.count+' |' })
  if($srcRows.Count -eq 0){ $srcRows=@('| n/a | 0 |') }
  $sigMd=@('# Finding Signals','','Matched: **'+$m.Count+'**','','## Source breakdown','| Source | Count |','|---|---|') + $srcRows + @('','## Top titles','| Title | Count |','|---|---|') + $sigRows
  Write-Utf8NoBom (Join-Path $ref 'finding-signals.md') ($sigMd -join "`n")

  $crossRows=@($cross | ForEach-Object { '| '+([string]$_.title).Replace('|','\\|')+' | '+$_.total_count+' | '+$_.unique_path_count+' |' })
  if($crossRows.Count -eq 0){ $crossRows=@('| (no multi-path recurring vulnerability title found) | 0 | 0 |') }
  $crossMd=@('# Cross Path Patterns','','| Vulnerability Title | Total Count | Unique Paths |','|---|---|---|') + $crossRows
  Write-Utf8NoBom (Join-Path $ref 'cross-path-patterns.md') ($crossMd -join "`n")

  $tri=@('# Triage Checklist','','- [ ] Confirm impacted trust boundary','- [ ] Confirm exploit prerequisites','- [ ] Attach code location evidence','- [ ] Compare same-title findings across paths')
  Write-Utf8NoBom (Join-Path $ref 'triage-checklist.md') ($tri -join "`n")

  if($pl.slug -eq 'oracle-flashloan-hot-potato-analysis'){
    $hotRg=[regex]::new('hot[- ]potato|热土豆|pricevouch|price voucher|must be destroyed|same transaction|flashloan',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $hot=@($m | Where-Object { $hotRg.IsMatch(([string]$_.title+' '+[string]$_.description+' '+[string]$_.suggestion)) })
    $hotTop=@($hot | Group-Object title | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object { '| '+([string]$_.Name).Replace('|','\\|')+' | '+$_.Count+' |' })
    if($hotTop.Count -eq 0){ $hotTop=@('| (no hot-potato-related match) | 0 |') }
    $hotMd=@('# Hot Potato Priority Signals','','Matched count: **'+$hot.Count+'**','','| Title | Count |','|---|---|') + $hotTop
    Write-Utf8NoBom (Join-Path $ref 'hot-potato-priority.md') ($hotMd -join "`n")
  }

  if($pl.slug -eq 'move-object-ptbs-analysis'){
    $moveM=@($m | Where-Object { $moveRegex.IsMatch(([string]$_.title+' '+[string]$_.description+' '+[string]$_.suggestion+' '+[string]$_.path)) })
    $moveTop=@($moveM | Group-Object title | Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object { '| '+([string]$_.Name).Replace('|','\\|')+' | '+$_.Count+' |' })
    if($moveTop.Count -eq 0){ $moveTop=@('| (no move-object-related match) | 0 |') }
    Write-Utf8NoBom (Join-Path $ref 'move-object-priority.md') ((@('# Move Object Priority Signals','','Matched: **'+$moveM.Count+'**','','| Title | Count |','|---|---|') + $moveTop) -join "`n")

    $ptbM=@($m | Where-Object { $ptbRegex.IsMatch(([string]$_.title+' '+[string]$_.description+' '+[string]$_.suggestion+' '+[string]$_.path)) })
    $ptbTop=@($ptbM | Group-Object title | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object { '| '+([string]$_.Name).Replace('|','\\|')+' | '+$_.Count+' |' })
    if($ptbTop.Count -gt 0){
      $ptbHdr=@(
        '# PTBs Priority Signals',
        '',
        ("Matched: **{0}**" -f [string]$ptbM.Count),
        '',
        '| Title | Count |',
        '|---|---|'
      )
      Write-Utf8NoBom (Join-Path $ref 'ptbs-priority.md') (($ptbHdr + $ptbTop) -join "`n")
    } else {
      $tpl=@('# PTBs Vulnerability Template','','当前数据源未识别到明确的 PTBs 漏洞样本。','','## 标题模板（待完善）','- [待完善] PTBs 顺序组合导致权限绕过','- [待完善] PTBs 多调用导致对象状态不一致','- [待完善] PTBs 交易块组合绕过单次限制')
      Write-Utf8NoBom (Join-Path $ref 'ptbs-priority.md') ($tpl -join "`n")
    }
  }
}

$market=[ordered]@{
  name='movesafe-security-skills'; owner=[ordered]@{name='MoveSafe'};
  metadata=[ordered]@{description='MoveSafe smart contract security skills bootstrapped from findings and ai_audit_findings data.';version='0.1.0-draft'};
  plugins=@($plugins | ForEach-Object { [ordered]@{name=$_.slug;source='./plugins/'+$_.slug;description=$_.title;version='0.1.0-draft';author=[ordered]@{name='MoveSafe'}} })
} | ConvertTo-Json -Depth 10
Write-Utf8NoBom (Join-Path $Root '.claude-plugin/marketplace.json') $market

$sum=[ordered]@{
  generated_at_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ');
  source_files=[ordered]@{findings=$FindingsPath; ai_audit_findings=$AiFindingsPath};
  parse_summary=[ordered]@{findings_valid=$parsedFindings.valid;findings_invalid_lines=$parsedFindings.bad;ai_valid=$parsedAi.valid;ai_invalid_chunks=$parsedAi.bad;total_valid=$records.Count};
  ai_vulnerability_types_top=$aiTypeTop;
  same_vuln_different_paths_top=$globalCross;
  move_object_ptbs_overview=[ordered]@{move_object_related_count=$moveGlobal.Count;ptbs_related_count=$ptbGlobal.Count};
  plugin_signal_summary=$pluginSignals
} | ConvertTo-Json -Depth 16
Write-Utf8NoBom (Join-Path $Root 'data/findings-summary.json') $sum

$aiRows=@($aiTypeTop | ForEach-Object { '| '+([string]$_.title).Replace('|','\\|')+' | '+$_.count+' |' }); if($aiRows.Count -eq 0){$aiRows=@('| (no ai vulnerability type) | 0 |')}
$aiHdr=@(
  '# AI Vulnerability Types',
  '',
  ("Source: {0}" -f [string]$AiFindingsPath),
  ("- Parsed valid records: **{0}**" -f [string]$parsedAi.valid),
  ("- Invalid chunks skipped: **{0}**" -f [string]$parsedAi.bad),
  '',
  '| Vulnerability Title | Count |',
  '|---|---|'
)
Write-Utf8NoBom (Join-Path $Root 'data/ai-vulnerability-types.md') (($aiHdr + $aiRows) -join "`n")

$gRows=@($globalCross | ForEach-Object { '| '+([string]$_.title).Replace('|','\\|')+' | '+$_.total_count+' | '+$_.unique_path_count+' |' }); if($gRows.Count -eq 0){$gRows=@('| (no global cross-path group found) | 0 | 0 |')}
Write-Utf8NoBom (Join-Path $Root 'data/same-vuln-different-paths.md') ((@('# Same Vulnerability Different Paths','','| Vulnerability Title | Total Count | Unique Paths |','|---|---|---|') + $gRows) -join "`n")
Write-Utf8NoBom (Join-Path $Root 'data/same-vuln-different-paths.json') ($globalCross | ConvertTo-Json -Depth 10)

$pb=@($pluginSignals | ForEach-Object { '- **'+$_.title+'** ('+$_.plugin+'): matched **'+$_.matched_count+'** findings' })
$readme=@(
  '# MoveSafe Skills (Draft)',
  '',
  'This repository is a fast bootstrap of a security skills project, modeled after qs_skills-main and seeded by historical findings data.',
  '',
  '## Author',
  '- audit911',
  '- Website: https://www.audit911.me/',
  '',
  '## Data source',
  ("- Findings source: {0}" -f [string]$FindingsPath),
  ("  - valid records: **{0}**" -f [string]$parsedFindings.valid),
  ("  - invalid lines skipped: **{0}**" -f [string]$parsedFindings.bad),
  ("- AI findings source: {0}" -f [string]$AiFindingsPath),
  ("  - valid records: **{0}**" -f [string]$parsedAi.valid),
  ("  - invalid chunks skipped: **{0}**" -f [string]$parsedAi.bad),
  ("- Total merged valid records: **{0}**" -f [string]$records.Count),
  '',
  '## Included plugins'
) + $pb + @(
  '',
  '## Notes',
  '- Same vulnerability across different file paths is auto-compared in each skill references/cross-path-patterns.md.',
  '- Move object and PTBs analysis is included in plugin move-object-ptbs-analysis.',
  '- If PTBs findings are absent in a source scope, a PTBs template marked as pending is auto-generated.'
)
Write-Utf8NoBom (Join-Path $Root 'README.md') ($readme -join "`n")

$skills=@(
  '# MoveSafe Skills Index (Draft)',
  '',
  'Autogenerated from findings and AI findings data to accelerate manual completion.',
  '',
  '## Snapshot',
  ("- Findings parsed: **{0}** (bad lines: {1})" -f [string]$parsedFindings.valid, [string]$parsedFindings.bad),
  ("- AI findings parsed: **{0}** (bad chunks: {1})" -f [string]$parsedAi.valid, [string]$parsedAi.bad),
  ("- Total merged records: **{0}**" -f [string]$records.Count),
  '',
  '## Plugin map'
) + $pb
Write-Utf8NoBom (Join-Path $Root 'skills.md') ($skills -join "`n")

Write-Output ('Generated MoveSafe skills project at: '+$Root)
Write-Output ('Plugins: '+$plugins.Count)
Write-Output ('Findings valid: '+$parsedFindings.valid+', AI valid: '+$parsedAi.valid+', total: '+$records.Count)
Write-Output ('Global move-object related: '+$moveGlobal.Count+', PTBs related: '+$ptbGlobal.Count)
