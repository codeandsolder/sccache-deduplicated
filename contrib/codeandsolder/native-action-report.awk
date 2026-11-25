/INFO +sccache::native_action\] native_action / {
    ++reports
    key = $(NF-2)
    source = $(NF-1)
    actual_mode = $NF
}
END {
    if (reports != 1 || length(key) != 64 || key !~ /^[0-9a-f]+$/ ||
        actual_mode != mode ||
        (source != "hit" && source != "worker" && source != "local") ||
        (mode == "refresh" && source == "hit")) exit 1
    print key, (exact_source ? source : (source == "hit" ? "hit" : "miss"))
}
