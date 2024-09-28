extern crate spotter;

fn main() {
    spotter::init();

    unsafe { std::ptr::null_mut::<i32>().write(42)};
}
