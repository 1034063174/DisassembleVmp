writeback = {"is_junk"}

local fixed = 0
for i, row in ipairs(rows) do
    if not row.is_junk then
        local all_dead = true
        for _, op in ipairs(row.pcode) do
            if op.opc_name ~= "CBRANCH" and op.opc_name ~= "BRANCH" and not op.dead then
                all_dead = false
                break
            end
        end
        if all_dead and #row.pcode > 0 then
            row.is_junk = true
            fixed = fixed + 1
            log(string.format("step %d: %s -> junk", row.step, row.asm))
        end
    end
end

log(string.format("[ok] 修复 %d 条假存活", fixed))