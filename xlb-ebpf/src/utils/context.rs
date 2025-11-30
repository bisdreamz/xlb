use aya_ebpf::programs::XdpContext;

#[inline(always)]
pub(crate) fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    // verifier needs to see this check
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}
