extern crate spotter;

fn main() {
    spotter::init();

    some_function();
}

fn some_function() {
    panic!("This is a panic!");
}
