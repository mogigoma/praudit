#ifndef ATTRIBUTES_H_
#define ATTRIBUTES_H_

struct attr_pair {
	char	*name;
	void	*result;
};

void	handleAttributes(const char *el, const char **attr, struct attr_pair *pairs);

#endif
