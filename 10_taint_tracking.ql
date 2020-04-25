/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr {
  // TODO: copy from previous step
  NetworkByteSwap(){
  exists(MacroInvocation m | m.getMacroName().regexpMatch("ntoh.*")   and 
    this=m.getExpr()) 
  }
}
 
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    // TODO
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    // TODO

exists( FunctionCall fc, Function f | 
fc.getTarget() = f and f.getName() = "memcpy" and sink.asExpr()=fc.getArgument(2) )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"

