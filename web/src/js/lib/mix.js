// Merge component fragments while keeping getters/setters live (object spread would evaluate them once).
export function mix(...sources) {
  const target = {}
  for (const src of sources) Object.defineProperties(target, Object.getOwnPropertyDescriptors(src))
  return target
}
