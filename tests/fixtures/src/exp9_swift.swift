// Experiment 9: Swift runtime
// Build with: swiftc -O
// Expected: _swift_* and _$s* symbols in imports
import Foundation

struct Point {
    var x: Double
    var y: Double

    func distance(to other: Point) -> Double {
        let dx = x - other.x
        let dy = y - other.y
        return (dx * dx + dy * dy).squareRoot()
    }
}

func main() {
    let a = Point(x: 1.0, y: 2.0)
    let b = Point(x: 4.0, y: 6.0)
    print("Distance: \(a.distance(to: b))")
}

main()
