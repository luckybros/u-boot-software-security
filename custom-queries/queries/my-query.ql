/**
 * @name Taint analysis from network to memcpy
 * @kind problem
 */


import cpp
import semmle.code.cpp.dataflow.TaintTracking
 
class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        // TODO: replace <class> and <var>
        exists(MacroInvocation m |
        m.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and
        m.getExpr() = this
      )
    }
}
 
module MyConfig implements DataFlow::ConfigSig {
 
    predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }
    predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall call | 
        call.getTarget().getName() = "memcpy" and
        sink.asExpr() = call.getArgument(2)
        )
    }

    predicate isBarrier(DataFlow::Node barrier) {
        exists(IfStmt ifs |
        barrier.asExpr() = ifs.getCondition().getAChild*())
    }
}
 
module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph
 
from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select source, sink, "Network byte swap flows to memcpy"
