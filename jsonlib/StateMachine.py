# Copyright (C) 2008 John Millikin. See LICENSE.txt for details.
# Author: John Millikin <jmillikin@gmail.com>

"""A simple push-down automaton.

Defines the main class StateMachine, and two stack operations: PUSH and POP.

"""

__all__ = ['PUSH', 'POP', 'StateMachine']

PUSH = 0
POP = 1

class StateMachine (object):
	"""A simple push-down automaton."""
	
	def __init__ (self, initial_state, initial_stack = ('')):
		self._state = initial_state
		self._stack = list (initial_stack)[:]
		self._transitions = {}
		
	def connect (self, state, stack, value, end_state, callback = None,
	             *stack_action):
		"""Connect a transition to a callback.
		
		state -- A string representing the expected state.
		stack -- The value that should be on the stack.
		value -- The value passed to transition.
		end_state -- The state to transition to.
		callback -- If not None, this function will be called with
		            any extra data passed to transition.
		stack_action -- The operation to perform on the stack, such
		                as PUSH, 'var'.
		
		"""
		key = (stack, state, value)
		
		if key in self._transitions:
			raise ValueError ("This state/stack/input combination "
			                  "has already been connected: %r" %
			                  [key])
			
		self._transitions[key] = (end_state, stack_action, callback)
		
	def connect_many (self, *transitions):
		"""Connect many transitions at once. 
		
		Each transition is in the format (stack, state, (value,
		end_state, callback, stack_action), ...).
		
		"""
		for state_def in transitions:
			stack, state = state_def[:2]
			connections = state_def[2:]
			for connection in connections:
				self.connect (state, stack, *connection)
				
	def transition (self, value, *args, **kwargs):
		"""Execute a transition between one state and another.
		
		value -- Combined with the current state and top of the
		         stack to discover the transition to take.
		*args, **kwargs -- Passed to the callback function, if it
		                   exists.
		
		"""
		key = (self._stack[-1], self._state, value)
		if key not in self._transitions:
			raise ValueError ("No such transition: %r" % (key,))
			
		end_state, stack_action, callback = self._transitions[key]
		try:
			if callback:
				retval = callback (*args, **kwargs)
			else:
				retval = None
				
			if stack_action:
				if stack_action[0] == PUSH:
					self._stack.append (stack_action[1])
				elif stack_action[0] == POP:
					self._stack.pop ()
			self._state = end_state
			return retval
			
		except:
			self._state = 'error'
			raise
			
